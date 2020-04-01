package main

//import "fmt"
import "net"

import "go.uber.org/zap"
import "bufio"
import "io"
import "github.com/vmihailenco/msgpack/v4"
import "github.com/wafuu-chan/switch-wifi-bridge/pkg/protocol"

type Client struct {
	Conn net.Conn
	// Unused
	MAC string
}

var log *zap.SugaredLogger
var clients = make(map[*Client]bool)

func main() {
	// TODO: Support passwords for simple privacy
	// TODO: Support user limit
	// TODO: Don't broadcast everything. Map MAC address
	zap, err := zap.NewDevelopment()
	if err != nil {
		log.Fatal(err)
	}
	log = zap.Sugar()
	defer log.Sync()

	log.Info("Listening.")
	ln, err := net.Listen("tcp", ":7331")
	if err != nil {
		log.Fatal(err)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Error(err)
		} else {
			go handleClient(conn)
		}
	}
}

func handleClient(conn net.Conn) {
	log.Info("New connection from", conn.RemoteAddr())
	self := &Client{Conn: conn}
	clients[self] = true
	defer conn.Close()
	defer delete(clients, self)

	// Buffer connection in case of fragmentation and other internet fun
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
			log.Info(message)
			// Broadcast to all clients
			for client := range clients {
				//if client == self {
				//	continue
				//}
				// Remarshal unmarshalled data prevent garbage from being sent downstream
				mpack, err := msgpack.Marshal(message)
				if err != nil {
					log.Error(err)
				} else {
					// Explicitly unbuffered to minimize latency
					// We can make some assumptions on packet size due to 802.11 limits
					client.Conn.Write(mpack)
				}
			}
		}
	}
	log.Info("Connection lost from", conn.RemoteAddr())
}
