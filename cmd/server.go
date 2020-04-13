package cmd

import "net"
import "io"

import "github.com/vmihailenco/msgpack/v4"
import "github.com/spf13/cobra"
import "github.com/wafuu-chan/switch-wifi-bridge/pkg/protocol"

// Client keeps track of different clients
type Client struct {
	Conn net.Conn
}

var clients = make(map[*Client]bool)

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
	self := &Client{Conn: conn}
	clients[self] = true
	defer conn.Close()
	defer delete(clients, self)

	decoder := protocol.StreamDecoder(conn)

	for {
		message, err := decoder.Decode()
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Error(err)
		} else { // Protocol unmarshal success
			log.Info(message)
			// Broadcast to all clients
			for client := range clients {
				// Don't send back your own packets
				if client == self {
					continue
				}
				// Remarshal unmarshalled data prevent garbage from being sent downstream
				mpack, err := msgpack.Marshal(message)
				if err != nil {
					log.Error(err)
				} else {
					// TODO: Put write side in separate goroutine
					// Explicitly unbuffered to minimize latency
					// We can make some assumptions on packet size due to 802.11 limits
					client.Conn.Write(mpack)
				}
			}
		}
	}
	log.Info("Connection lost from", conn.RemoteAddr())
}
