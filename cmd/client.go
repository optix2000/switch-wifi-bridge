package cmd

import "bytes"
import "io"
import "net"
import "os"
import "os/exec"
import "strconv"
import "time"

import "golang.org/x/sync/syncmap"
import "github.com/google/gopacket"
import "github.com/google/gopacket/pcap"
import "github.com/google/gopacket/pcapgo"
import "github.com/google/gopacket/layers"
import "github.com/safchain/ethtool"
import "github.com/spf13/cobra"
import "github.com/wafuu-chan/switch-wifi-bridge/pkg/protocol"
import "github.com/wafuu-chan/switch-wifi-bridge/pkg/wifiutils"

var switchMACs = syncmap.Map{}

var clientCmd = &cobra.Command{
	Use:   "client [server:port]",
	Short: "Start client and connect to server",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		client(args[0])
	},
}

// TODO: Refactor this. Probably into some sort of connection struct
var send chan<- []byte
var inject chan<- []byte

// Flags
var iface string
var noMon bool
var noPromisc bool
var noHop bool
var altMon bool
var dumpPackets string

// Driver compat flags
var isMAC80211 bool

func init() {
	clientCmd.Flags().StringVarP(&iface, "interface", "i", "", "Wireless interface to use for bridge. (Examples: wlan0, wlp5s0) (required)")
	clientCmd.Flags().BoolVarP(&noMon, "no-monitor", "M", false, "Don't put interface in monitor mode. This should only be used if you're putting the interface in monitor mode yourself (ie using airmon-ng or iw)")
	clientCmd.Flags().BoolVarP(&noPromisc, "no-promiscuous", "P", false, "Don't put interface in promiscuous mode. This should only be used if your driver is always in promiscuous mode but doesn't support setting it.")
	clientCmd.Flags().BoolVarP(&noHop, "no-channel-hopping", "H", false, "Don't channel hop while discovering. This should only be used if you know the channel of your device or have an alternate channel switching method.")
	clientCmd.Flags().BoolVarP(&altMon, "alt-monitor", "m", false, "Use alternative monitor mode using 'iw set monitor' instead of libpcap.")
	clientCmd.Flags().StringVarP(&dumpPackets, "dump-packets", "D", "", "Dump captured packets to specified file.")

	clientCmd.MarkFlagRequired("interface")
}

// TODO: Add reconnection
// TODO: Anonymize MAC
// TODO: Refactor variables so things have better interfaces
// Server can have types for starting goroutines for network related things
// TODO: Prevent probe spamming/brute forcing
// TODO: Add some timed debug prints for packets sent/recieved to reduce spam
func client(serverAddr string) {
	handle := initClient()
	defer handle.Close()

	// Start injection goroutine
	inject = initInjector(handle)

	// Start network goroutines
	send = initConnection(serverAddr, handle)

	// Start channel hopping
	// TODO: Probably a nicer way of cancelling this
	stopHop := make(chan struct{})
	if !noHop {
		go channelHopper(stopHop, iface)
	} else {
		close(stopHop)
	}

	var pcapDumpWriter *pcapgo.Writer
	if dumpPackets != "" {
		log.Info("Writing packets to ", dumpPackets)
		pcapDumpFile, err := os.Create(dumpPackets)
		if err != nil {
			log.Fatal("Error while creating pcap file: ", err)
		}
		defer pcapDumpFile.Close()
		pcapDumpWriter = pcapgo.NewWriter(pcapDumpFile)
		err = pcapDumpWriter.WriteFileHeader(uint32(handle.SnapLen()), handle.LinkType())
		if err != nil {
			log.Fatal("Error while writing pcap header: ", err)
		}
	}

	// Packet reading loop
	packetS := gopacket.NewPacketSource(handle, handle.LinkType())
	packetS.DecodeOptions.Lazy = true
	// TODO: Move this to a goroutine?
	for packet := range packetS.Packets() {
		// Dump packets for debuggin
		if pcapDumpWriter != nil {
			err := pcapDumpWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			if err != nil {
				log.Error("Error while dumping packet: ", err)
			}
		}

		// Sanity checks
		layer := packet.Layer(layers.LayerTypeRadioTap)
		if layer == nil {
			// Should be easy unless Switch changes PHY modes
			log.Error("RadioTap header not found. This likely means your wifi card does not support monitor mode.")
			log.Debug("Packet: ", packet)
			continue
		}
		rtap := layer.(*layers.RadioTap)
		// Naively trust the RT header for speed
		// TODO: Check FCS forreal using dot11
		if rtap.Flags.BadFCS() {
			log.Debug("Found corrupt packet. Discarding.")
			continue
		}
		layer = packet.Layer(layers.LayerTypeDot11)
		if layer == nil {
			if packet.Metadata().Truncated {
				log.Debug("Found truncated packet. Discarding.")
				continue
			}
			err := packet.ErrorLayer()
			if err != nil {
				log.Debug("Error parsing packet. Discarding.")
				log.Debug(err)
				continue
			}
			log.Warn("Dot11 header not found. This likely means your wifi card does not support monitor mode.")
			log.Debug("Packet: ", packet)
			continue
		} else {
			// TODO:
			// Need to implement normal acks. Can try to ignore/fail add block ack requests to stay with normal acks. Might not work with 802.11n since it's supposed to support it in the standard.
			// For speed we can try to implement block acks after it switches to n mode, and rts/cts

			// Forward packets if they match whitelist
			dot11 := layer.(*layers.Dot11)
			_, ok := switchMACs.Load(dot11.Address2.String())
			if ok {
				// Ack received packet so we don't get retries
				inject <- wifiutils.FastAck(dot11.Address2, rtap.ChannelFrequency)
				forwardPacket(send, packet)
				// Skip detection if we forward a packet
				continue
			}

			// Look for packets in response to broadcast
			_, ok = switchMACs.Load(dot11.Address1.String())
			if ok {
				// Drop any acks since we'll be sending our own
				if len(dot11.Address2) != 0 {
					if !registerSwitch(dot11) {
						inject <- wifiutils.FastAck(dot11.Address2, rtap.ChannelFrequency)
						// Pin channel to where switch was detected
						// NB: Assumptions made here that any other switches will join the first one
						if !noHop {
							log.Info("Locking channel to ", freqToChan(rtap.ChannelFrequency))
							stopHop <- struct{}{}
							close(stopHop)
							changeChannel(iface, freqToChan(rtap.ChannelFrequency))
							noHop = true
						}
					}
					forwardPacket(send, packet)
					continue
				}
			}

			// Scan for Switch broadcasts
			// Try looking for Switch specific Action frames
			layer = packet.Layer(layers.LayerTypeDot11MgmtAction)
			if layer != nil {
				action := layer.(*layers.Dot11MgmtAction)
				if action.Contents[0] == '\x7f' {
					log.Debug("Found Vendor specific Action")
					// Check for Nintendo OUI
					if bytes.Compare(action.Contents[1:4], []byte("\x00\x22\xaa")) == 0 {
						if !registerSwitch(dot11) {
							// Pin channel to where switch was detected
							// NB: Assumptions made here that any other switches will join the first one
							if !noHop {
								log.Info("Locking channel to ", freqToChan(rtap.ChannelFrequency))
								stopHop <- struct{}{}
								close(stopHop)
								changeChannel(iface, freqToChan(rtap.ChannelFrequency))
								noHop = true
							}
						}
						forwardPacket(send, packet)
						continue
					}
				}
			}
			// TODO: Implement me
			// Try looking for Switch using OUI from broadcast request
			//layer = packet.Layer(layers.LayerTypeDot11MgmtProbeReq)
			//if layer != nil {
			//}
		}
	}
}

func initClient() *pcap.Handle {
	if altMon {
		altMonitor(iface)
	}

	inactivePcap, err := pcap.NewInactiveHandle(iface)
	if err != nil {
		log.Fatal("Could not attach to interface: ", err)
	}

	if noMon {
		log.Info("Skipping monitor mode")
	} else {
		err = inactivePcap.SetRFMon(true)
		if err != nil {
			log.Error("Could not enter monitor mode: ", err)
		}
	}

	if noPromisc {
		log.Info("Skipping promiscuous mode")
	} else {
		inactivePcap.SetPromisc(true)
		if err != nil {
			log.Error("Could not enter promiscuous mode: ", err, ". Some packets may not be captured.")
		}
	}
	// 802.11 is latency sensitive. Would rather lose packets than get them late
	inactivePcap.SetImmediateMode(true)

	handle, err := inactivePcap.Activate()
	if err != nil {
		log.Fatal("Could not activate pcap: ", err)
	}
	log.Info("Pcap started.")

	return handle
}

// Network goroutine handling connections
func initConnection(serverAddr string, handle *pcap.Handle) chan<- []byte {
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		log.Fatal(err)
	}
	channel := make(chan []byte, 1024)

	go func(conn net.Conn, handle *pcap.Handle) {
		log.Info("Connected to ", conn.RemoteAddr())
		defer conn.Close()

		// Write side
		go func(conn net.Conn, messages <-chan []byte) {
			for message := range messages {
				conn.Write(message)
			}
		}(conn, channel)

		defer close(channel)
		decoder := protocol.StreamDecoder(conn)

		for {
			message, err := decoder.Decode()
			if err != nil {
				if err == io.EOF {
					break
				}
				log.Error("Error deserializing msgpack: ", err)
			} else { // Protocol unmarshal success
				switch message.Type {
				case protocol.TypeError:
					log.Error("Server returned error: ", message.Error)
				case protocol.TypePacket:
					log.Debug("Injecting packet")
					injectPacket(handle, message.Packet)
				case protocol.TypeRegister:
					handleRegister(message)
				default:
					log.Error("Invalid protocol type: ", message.Type)
					log.Debug(message)

				}
			}
		}
		// Fatal since we don't try to reconnect
		log.Fatal("Connection to server lost.")
	}(conn, handle)

	return channel
}

func initInjector(handle *pcap.Handle) chan<- []byte {
	channel := make(chan []byte, 1024)

	go func(handle *pcap.Handle, packets <-chan []byte) {
		for packetData := range packets {
			err := handle.WritePacketData(packetData)
			if err != nil {
				log.Error("Error while injecting packet: ", err)
			}
		}
	}(handle, channel)

	return channel
}

func handleRegister(message *protocol.Protocol) {
	log.Debug("Received registration packet")
	remoteMACs := make(map[string]bool)
	for _, mac := range message.Registration {
		remoteMACs[mac] = true
	}

	// Remote list is canonical.
	switchMACs.Range(
		func(key, val interface{}) bool {
			mac := key.(string)
			_, ok := remoteMACs[mac]
			if !ok {
				local := val.(bool)
				// Don't delete locally found MACs
				if !local {
					log.Debug("De-registering remote Switch ", mac)
					globalMACList.Delete(mac)
				}
			}
			return true
		},
	)

	for _, mac := range message.Registration {
		_, ok := switchMACs.Load(mac)
		if !ok {
			log.Debug("Registering remote Switch ", mac)
			switchMACs.Store(mac, false)
		}
	}
}

// TODO: Refactor to use struct for static paramenters
func forwardPacket(send chan<- []byte, packet gopacket.Packet) {
	mpack, err := protocol.MarshalPacket(packet.Data())
	if err != nil {
		log.Fatal(err)
	}
	send <- mpack
}

// TODO: Make more generic
// Have "DB" feature, mapping driver + version -> injection, mac80211 support
func detectIface(iface string) {
	ethHandle, err := ethtool.NewEthtool()
	if err != nil {
		log.Error(err)
	}
	defer ethHandle.Close()

	driver, err := ethHandle.DriverName(iface)
	if err != nil {
		log.Error(err)
	}
	log.Info(iface, " is using ", driver)
	if driver == "ath9k" {
		log.Debug("mac80211 driver")
		isMAC80211 = true
	}
}

func injectPacket(handle *pcap.Handle, packetData []byte) {
	// Do compat

	// Strip FCS for older nl80211/cfg80211 drivers
	// mac80211 will strip it for us. Older drivers will not
	if !isMAC80211 {
		packet := gopacket.NewPacket(packetData, layers.LayerTypeRadioTap, gopacket.Lazy)
		layer := packet.Layer(layers.LayerTypeRadioTap)
		radiotap := layer.(*layers.RadioTap)

		if radiotap.Flags.FCS() {
			packetData = packetData[:len(packetData)-4]
		}
	}

	// TODO: Fixme
	inject <- packetData
}

func registerSwitch(dot11 *layers.Dot11) bool {
	_, ok := switchMACs.LoadOrStore(dot11.Address2.String(), true)
	if !ok {
		log.Info("Found Switch at ", dot11.Address2, ". Forwarding packets")

		// Send updated list to server
		var registrationlist []string
		switchMACs.Range(
			func(key, val interface{}) bool {
				v := val.(bool)
				if v {
					k := key.(string)
					registrationlist = append(registrationlist, k)
				}
				return true
			},
		)

		message, err := protocol.MarshalRegistration(registrationlist)
		if err != nil {
			log.Error(err)
		}
		// TODO: fixme
		send <- message
	}
	return ok
}

// Hack for an alternative monitor mode. Needed for some drivers as they can't set monitor mode while the interface is up.
func altMonitor(iface string) {
	log.Info("Using alternative monitor mode")

	log.Info("Bringing ", iface, " down")
	execLog("ip", "link", "set", iface, "down")

	log.Info("Setting monitor mode.")
	execLog("iw", iface, "set", "monitor", "none")

	log.Info("Bringing ", iface, " up")
	execLog("ip", "link", "set", iface, "up")
}

func execLog(command string, args ...string) error {
	cmd := exec.Command(command, args...)
	log.Debug(cmd)
	err := cmd.Run()
	if err != nil {
		log.Error(cmd, ": ", err)
	}
	return err
}

// Crude channel hopper
func channelHopper(abort <-chan struct{}, iface string) {
	i := 1
	for {
		select {
		case <-abort:
			return
		default:
		}
		changeChannel(iface, i)
		i++
		// TODO: Detect regulatory domain and remove hardcode
		if i > 11 {
			i = 1
		}
		time.Sleep(time.Millisecond * 100)
	}
}

// TODO: Replace with netlink instead of shelling out
// Too bad there's no good netlink nl80211 libraries out there.
func changeChannel(iface string, channel int) {
	execLog("iw", iface, "set", "channel", strconv.Itoa(channel))
}

// NB: Only works for 2.4Ghz for channels 1-13
func freqToChan(freq layers.RadioTapChannelFrequency) int {
	return int((freq - 2407) / 5)
}
