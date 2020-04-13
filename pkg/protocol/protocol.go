package protocol

import "bufio"
import "io"

import "github.com/vmihailenco/msgpack/v4"

// Protocol is a super simple client/server protocol for passing packets over messagepack
type Protocol struct {
	_msgpack struct{} `msgpack:",omitempty"`
	Version  int
	Error    string
	Packet   []byte
	// Reserved, not implemented
	// Broadcast bool
}

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

// DecodeStream returns a channel of protocols from a reader
func (decoder *Decoder) Decode() (*Protocol, error) {

	message := &Protocol{}
	err := decoder.Decoder.Decode(message)
	if err != nil {
		return nil, err
	}
	return message, nil
}
