package cmd

import "time"
import "encoding/hex"

import "github.com/google/gopacket"
import "github.com/google/gopacket/pcap"
import "github.com/spf13/cobra"

var testCmd = &cobra.Command{
	Use:   "test",
	Short: "Test",
	Args:  cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		test()
	},
}

var channel int

func init() {
	testCmd.Flags().StringVarP(&iface, "interface", "i", "", "Wireless interface to use for bridge. (Examples: wlan0, wlp5s0) (required)")
	testCmd.Flags().BoolVarP(&noMon, "no-monitor", "M", false, "Don't put interface in monitor mode. This should only be used if you're putting the interface in monitor mode yourself (ie using airmon-ng or iw)")
	testCmd.Flags().BoolVarP(&noPromisc, "no-promiscuous", "P", false, "Don't put interface in promiscuous mode. This should only be used if your driver is always in promiscuous mode but doesn't support setting it.")
	testCmd.Flags().BoolVarP(&altMon, "alt-monitor", "m", false, "Use alternative monitor mode using 'iw set monitor' instead of libpcap.")
	testCmd.Flags().IntVarP(&channel, "channel", "c", 1, "channel to bind to")

	clientCmd.MarkFlagRequired("interface")
}

func test() {
	if altMon {
		altMonitor(iface)
	}

	changeChannel(iface, channel)

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
	inactivePcap.SetTimeout(pcap.BlockForever)

	handle, err := inactivePcap.Activate()
	if err != nil {
		log.Fatal("Could not activate pcap: ", err)
	}
	log.Info("Pcap started.")

	defer handle.Close()

	shandle, err := pcap.OpenOffline("sample.pcap")
	if err != nil {
		log.Fatal(err)
	}

	// Packet reading loop
	packetS := gopacket.NewPacketSource(shandle, shandle.LinkType())
	packetS.DecodeOptions.Lazy = true
	// TODO: Move this to a goroutine?
	var packets [][]byte
	for packet := range packetS.Packets() {
		log.Info(packet)
		// Append orig
		packetData := packet.Data()
		packets = append(packets, packetData)
		packets = append(packets, packetData[:len(packetData)-4])
	}
	shandle.Close()
	go func() {
		for {
			time.Sleep(time.Millisecond * 100)
			log.Debug("Injecting packets")
			for _, packet := range packets {
				log.Debug(hex.Dump(packet))
				err := handle.WritePacketData(packet)
				if err != nil {
					log.Error(err)
				}
			}
		}
	}()
	sink := gopacket.NewPacketSource(handle, handle.LinkType())
	for range sink.Packets() {
	}
}
