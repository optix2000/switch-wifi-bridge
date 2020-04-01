package main

import "net"
import "bytes"
import "bufio"
import "io"

import "go.uber.org/zap"
import "github.com/google/gopacket"
import "github.com/google/gopacket/pcap"
import "github.com/google/gopacket/layers"
import "github.com/vmihailenco/msgpack/v4"
import "github.com/wafuu-chan/switch-wifi-bridge/pkg/protocol"

var log *zap.SugaredLogger
var switchMacs = map[string]bool{}

func main() {
	// TODO: Anonymize MAC
	// TODO:
	zap, err := zap.NewDevelopment()
	if err != nil {
		log.Fatal(err)
	}
	log = zap.Sugar()
	defer log.Sync()

	conn, err := net.Dial("tcp", "192.168.1.56:7331")
	if err != nil {
		log.Fatal(err)
	}

	inactivePcap, err := pcap.NewInactiveHandle("wlan0mon")
	if err != nil {
		log.Fatal("Could not attach to interface: ", err)
	}
	err = inactivePcap.SetRFMon(true)
	if err != nil {
		log.Error("Could not enter monitor mode: ", err)
	}
	inactivePcap.SetPromisc(true)
	if err != nil {
		log.Error("Could not enter promiscuous mode: ", err, ". Some packets may not be captured.")
	}
	inactivePcap.SetTimeout(pcap.BlockForever)

	handle, err := inactivePcap.Activate()
	if err != nil {
		log.Fatal("Could not activate pcap: ", err)
	}
	log.Info("Pcap started.")

	defer handle.Close()

	// Start injection goroutine
	go handlePackets(conn, handle)

	// Packet reading loop
	packetS := gopacket.NewPacketSource(handle, handle.LinkType())
	packetS.DecodeOptions.Lazy = true
	for packet := range packetS.Packets() {
		log.Debug("Packet: ", packet)
		// Sanity check
		layer := packet.Layer(layers.LayerTypeRadioTap)
		if layer == nil {
			// TODO?: Generate radiotap headers if they aren't being captured
			// Should be easy unless Switch changes PHY modes
			log.Warn("RadioTap header not found. This likely means your wifi card does not support monitor mode.")
			log.Debug("Packet: ", packet)
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
			// Forward packets if they match whitelist
			dot11 := layer.(*layers.Dot11)
			if switchMacs[dot11.Address1.String()] {
				// Skip detection if we forward a packet
				forwardPacket(conn, packet)
				continue
			}
			// Scan for Switches
			// Try looking for Switch specific Action frames
			layer = packet.Layer(layers.LayerTypeDot11MgmtAction)
			if layer != nil {
				action := layer.(*layers.Dot11MgmtAction)
				if action.Contents[0] == '\x7f' {
					log.Debug("Found Vendor specific Action")
					if bytes.Compare(action.Contents[1:4], []byte("\x00\x22\xaa")) == 0 {
						registerSwitch(dot11)
						forwardPacket(conn, packet)
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

func forwardPacket(conn net.Conn, packet gopacket.Packet) {
	message := protocol.Protocol{Version: 0, Packet: packet.Data()}
	mpack, err := msgpack.Marshal(message)
	if err != nil {
		log.Fatal(err)
	}
	log.Debug("Forwarding packet: ", message)
	// TODO: Convert to channel
	conn.Write(mpack)
}

func registerSwitch(dot11 *layers.Dot11) {
	log.Info("Found Switch at ", dot11.Address2, ". Forwarding packets")
	switchMacs[dot11.Address2.String()] = true
}

func handlePackets(conn net.Conn, handle *pcap.Handle) {
	log.Info("Connected to ", conn.RemoteAddr())
	defer conn.Close()
	// TODO: Move protocol decode to lib
	reader := bufio.NewReader(conn)
	decoder := msgpack.NewDecoder(reader)

	message := &protocol.Protocol{}
	for {
		err := decoder.Decode(message)
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Error(err)
		} else { // Protocol unmarshal success
			log.Debug(message)
			handle.WritePacketData(message.Packet)
		}
	}
	// Fatal since we don't try to reconnect
	// TODO: Add reconnection
	log.Fatal("Connection to server lost.")
}
