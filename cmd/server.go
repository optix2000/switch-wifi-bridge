package cmd

import "net"
import "io"

import "golang.org/x/sync/syncmap"
import "github.com/spf13/cobra"
import "github.com/wafuu-chan/switch-wifi-bridge/pkg/protocol"

// Client keeps track of different clients
type Client struct {
	Conn    net.Conn
	MACList map[string]bool
	Send    chan []byte
}

var globalMACList = syncmap.Map{}

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

// Flags
var reflect bool

func init() {
	serverCmd.Flags().BoolVarP(&reflect, "reflect", "r", false, "Reflect packets back to the client that sent them. Should only use for testing purposes as this will duplicate packets on all clients.")

	serverCmd.Flags().MarkHidden("reflect")
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
			log.Debug("Sent packet to ", conn.RemoteAddr())
			_, err := conn.Write(message)
			if err != nil {
				log.Error(err)
			}
		}

	}(conn, self.Send)

	clients.Store(self, true)

	defer close(self.Send)
	defer conn.Close()
	defer clients.Delete(self)

	decoder := protocol.StreamDecoder(conn)

	// Seed client with maclist
	self.broadcastRegister()

	for {
		message, err := decoder.Decode()
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Error(err)
		} else { // Protocol unmarshal success
			switch message.Type {
			case protocol.TypeError:
				self.handleError(message)
			case protocol.TypePacket:
				self.handlePacket(message)
			case protocol.TypeRegister:
				self.handleRegister(message)
			default:
				log.Error("Invalid protocol type: ", message.Type)
				log.Debug(message)
			}
		}
	}
	log.Info("Connection lost from", conn.RemoteAddr())
	self.deregisterClient()
}

func (self *Client) handlePacket(message *protocol.Protocol) {
	log.Debug("Received packet from ", self.Conn.RemoteAddr().String())
	// Broadcast to all clients
	mpack, err := protocol.MarshalPacket(message.Packet)
	if err != nil {
		log.Error(err)
	}
	self.broadcastMessage(mpack)
}

func (self *Client) handleError(message *protocol.Protocol) {
	log.Error("Error received from " + self.Conn.RemoteAddr().String() + ": " + message.Error)
}

func (self *Client) handleRegister(message *protocol.Protocol) {
	log.Debug("Received register from ", self.Conn.RemoteAddr().String())
	// Naive way of doing set differences
	remoteMACs := make(map[string]bool)
	for _, mac := range message.Registration {
		remoteMACs[mac] = true
	}

	// Remote list is canonical.
	for mac := range self.MACList {
		_, ok := remoteMACs[mac]
		if !ok {
			delete(self.MACList, mac)
			globalMACList.Delete(mac)
		}
	}

	for _, mac := range message.Registration {
		_, ok := self.MACList[mac]
		if !ok {
			// Sanity check for duplicate MACs across clients
			_, exists := globalMACList.Load(mac)
			if exists {
				log.Warn("MAC ", mac, " from ", self.Conn.RemoteAddr().String(), " already exists from another client. Multiple clients running or something naughty is going on. Skipping.")
				msg, err := protocol.MarshalError("MAC " + mac + " already exists on another client. Registration rejected.")
				if err != nil {
					log.Error(err)
				} else {
					self.Send <- msg
				}
			} else {
				globalMACList.Store(mac, true)
			}
		}
	}
	self.broadcastRegister()
}

func (self *Client) deregisterClient() {
	log.Debug("Deregistering client ", self.Conn.RemoteAddr, " with MACs: ", self.MACList)
	for mac := range self.MACList {
		globalMACList.Delete(mac)
	}
	self.broadcastRegister()
}

func (self *Client) broadcastRegister() {
	// Broadcast new macList
	macList := []string{}
	globalMACList.Range(
		func(key, val interface{}) bool {
			mac := key.(string)
			macList = append(macList, mac)
			return true
		},
	)
	log.Debug("Broadcasting maclist ", macList)
	msg, err := protocol.MarshalRegistration(macList)
	if err != nil {
		log.Error(err)
	} else {
		self.broadcastMessage(msg)
	}
}

func (self *Client) broadcastMessage(mpack []byte) {
	clients.Range(
		func(key, val interface{}) bool {
			client := key.(*Client)
			// Don't send back your own packets
			if client == self && !reflect {
				return true
			}
			log.Debug("Packet forwarded to ", client.Conn.RemoteAddr())
			client.Send <- mpack
			return true
		},
	)
}
