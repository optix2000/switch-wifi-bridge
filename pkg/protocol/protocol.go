package protocol

import "bufio"
import "errors"
import "io"
import "strconv"

import "github.com/vmihailenco/msgpack/v4"

// Protocol is a super simple client/server protocol for passing packets over messagepack
type Protocol struct {
	_msgpack struct{} `msgpack:",omitempty"`

	Version      int
	Type         Type
	Error        string
	Registration []string
	Packet       []byte
}

// ProtocolVersion is supported protocol version of this lib
const ProtocolVersion = 1

type Type int

const (
	// TypeError is the packet type for errors
	TypeError Type = iota
	// TypeRegister is the packet type for MAC registration/propagation
	TypeRegister
	// TypePacket is the packet type for packet forwarding
	TypePacket
)

type Decoder struct {
	Reader  *bufio.Reader
	Decoder *msgpack.Decoder
}

// MarshalPacket takes in raw packet data and creates a messagepack to send
func MarshalPacket(packet []byte) ([]byte, error) {
	message := Protocol{Version: 0, Packet: packet}
	mpack, err := msgpack.Marshal(message)
	if err != nil {
		return nil, err
	}
	return mpack, nil
}

func StreamDecoder(reader io.Reader) *Decoder {
	ret := &Decoder{}
	ret.Reader = bufio.NewReader(reader)
	ret.Decoder = msgpack.NewDecoder(reader)
	return ret
}

// Decode returns the next decoded packet
func (decoder *Decoder) Decode() (*Protocol, error) {

	message := &Protocol{}
	err := decoder.Decoder.Decode(message)
	if err != nil {
		return nil, err
	}
	if message.Version != ProtocolVersion {
		err = errors.New("Protocol Version Mismatch: Got v" + strconv.Itoa(message.Version) + " expected v" + strconv.Itoa(ProtocolVersion))
	}
	return message, err
}
