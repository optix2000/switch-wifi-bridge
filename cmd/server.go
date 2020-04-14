package cmd

import "net"
import "io"

import "golang.org/x/sync/syncmap"
import "github.com/vmihailenco/msgpack/v4"
import "github.com/spf13/cobra"
import "github.com/wafuu-chan/switch-wifi-bridge/pkg/protocol"

// Client keeps track of different clients
type Client struct {
	Conn net.Conn
	Send chan []byte
}

var clients = syncmap.Map{}

var serverCmd = &cobra.Command{
	Use:   "server [bindaddr:port]",
	Short: "Start server. (Defaults to :7331)",
	Args:  cobra.RangeArgs(0, 1),
	Run: func(cmd *cobra.Command, args []string) {
		var listenAddr string
		if len(args) < 1 {
			listenAddr = ":7331"
		} else {
			listenAddr = args[0]
		}
		server(listenAddr)
	},
}

func server(listenAddr string) {
	// TODO: Support passwords for simple privacy
	// TODO: Support user limit
	// TODO: Don't broadcast everything. Map MAC address

	log.Info("Listening on ", listenAddr)
	ln, err := net.Listen("tcp", listenAddr)
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

// Goroutine for handling each client in parallel
func handleClient(conn net.Conn) {
	log.Info("New connection from ", conn.RemoteAddr())
	self := &Client{
		Conn: conn,
		Send: make(chan []byte, 1024),
	}

	// async writer
	go func(conn net.Conn, send <-chan []byte) {
		for message := range send {
			// Explicitly unbuffered to minimize latency
			// We can make some assumptions on packet size due to 802.11 limits
			conn.Write(message)
		}

	}(conn, self.Send)

	clients.Store(self, true)

	defer close(self.Send)
	defer conn.Close()
	defer clients.Delete(self)

	decoder := protocol.StreamDecoder(conn)

	for {
		message, err := decoder.Decode()
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Error(err)
		} else { // Protocol unmarshal success
			log.Debug(message)
			// Broadcast to all clients
			clients.Range(
				func(key, val interface{}) bool {
					client := key.(*Client)
					// Don't send back your own packets
					if client == self {
						return true
					}
					// Remarshal unmarshalled data prevent garbage from being sent downstream
					mpack, err := msgpack.Marshal(message)
					if err != nil {
						log.Error(err)
					} else {
						client.Send <- mpack
					}
					return true
				},
			)
		}
	}
	log.Info("Connection lost from", conn.RemoteAddr())
}
