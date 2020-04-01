package protocol

type Protocol struct {
	_msgpack struct{} `msgpack:",omitempty"`
	Version  int
	Error    string
	Packet   []byte
	// Reserved, not implemented
	// Broadcast bool
}
