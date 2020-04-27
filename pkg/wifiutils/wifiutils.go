package wifiutils

import "net"
import "encoding/binary"
import "github.com/google/gopacket"
import "github.com/google/gopacket/layers"

// FastAck returns a pre-built ack frame quickly
func FastAck(mac net.HardwareAddr, channel layers.RadioTapChannelFrequency) []byte {
	raw := []byte("\x00\x00\x0e\x00\x0e\x00\x00\x00\x10\x02\x00\x00\xa0\x00\xd4\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
	// Overwite mac
	copy(raw[len(raw)-10:len(raw)-4], mac)
	// Overwrite channel
	binary.LittleEndian.PutUint16(raw[10:12], uint16(channel))

	return raw
}

// Ack serializes an Ack frame with custom radiotap
func Ack(mac net.HardwareAddr, channel layers.RadioTapChannelFrequency) []byte {
	// gopacket serialization is a bit off.
	// Radiotap has too many headers even if they aren't present.
	// Dot11 generates a full 2x10 byte packet for Acks, even if there isn't supposed to be anything in them.
	radiotap := &layers.RadioTap{
		Present:          layers.RadioTapPresentFlags + layers.RadioTapPresentRate + layers.RadioTapPresentChannel,
		Flags:            layers.RadioTapFlagsFCS,
		Rate:             2, // rate is diveded by 2
		ChannelFrequency: channel,
		ChannelFlags:     layers.RadioTapChannelFlagsGhz2 + layers.RadioTapChannelFlagsCCK,
	}
	dot11 := &layers.Dot11{
		Type:     layers.Dot11TypeCtrlAck,
		Address1: mac,
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buf, opts, radiotap, dot11)

	return buf.Bytes()
}
