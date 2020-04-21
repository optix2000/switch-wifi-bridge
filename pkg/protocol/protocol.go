package protocol

import "bufio"
import "errors"
import "io"
import "strconv"

import "github.com/vmihailenco/msgpack/v4"

// Protocol is a super simple client/server protocol for passing packets over messagepack
type Protocol struct {
	_msgpack struct{} `msgpack:",omitempty"`

	// Required
	Version int
	Type    Type

	// Fields dependent on type
	Error        string
	Registration []string
	Packet       []byte
}

// ProtocolVersion is supported protocol version of this lib
const ProtocolVersion = 1

type Type int

const (
	// TypeInvalid reserves 0 for validity checking. Should never be used outside of error checking
	TypeInvalid Type = iota
	// TypeError is the packet type for errors
	TypeError
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
	message := Protocol{Version: ProtocolVersion, Type: TypePacket, Packet: packet}
	mpack, err := msgpack.Marshal(message)
	if err != nil {
		return nil, err
	}
	return mpack, nil
}

// MarshalRegistration takes in mac registration and creates a messagepack to send
func MarshalRegistration(registration []string) ([]byte, error) {
	message := Protocol{Version: ProtocolVersion, Type: TypeRegister, Registration: registration}
	mpack, err := msgpack.Marshal(message)
	if err != nil {
		return nil, err
	}
	return mpack, nil
}

// MarshalError takes in an error and creates a messagepack to send
func MarshalError(errString string) ([]byte, error) {
	message := Protocol{Version: ProtocolVersion, Type: TypeError, Error: errString}
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

	// Sanity check everything
	switch message.Type {
	case TypeInvalid:
		err = errors.New("Invalid Protocol Type")
	case TypeError:
		if message.Error == "" {
			err = errors.New("Error type, but no error message received")
		}
	case TypePacket:
		if len(message.Packet) == 0 {
			err = errors.New("Packet type, but no packet received")
		}
	case TypeRegister:
		if len(message.Registration) == 0 {
			err = errors.New("Register type, but no MACs received")
		}
	}
	return message, err
}
