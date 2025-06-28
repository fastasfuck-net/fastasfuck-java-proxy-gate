package nobackendserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"log"
	"net"
	"os"

	"go.minekube.com/gate/pkg/edition/java"
)

var Plugin = java.PluginFunc(startFakeServer)

func startFakeServer(ctx context.Context, srv *java.Server) error {
	go func() {
		listener, err := net.Listen("tcp", ":25566")
		if err != nil {
			log.Println("Fehler beim Starten des Fake-Servers:", err)
			return
		}
		log.Println("Fake-Server läuft auf Port 25566...")

		iconb := loadServerIconB()

		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Println("Verbindungsfehler:", err)
				continue
			}
			go handleConnectionB(conn, iconb)
		}
	}()
	return nil
}

// Einstellungen
const (
	motdB       = "§aMini-Server §7» §eNur Ping & Kick"
	kickReasonB = "§cDu wurdest gekickt!"
)

func loadServerIconB() string {
	data, err := os.ReadFile("server-icon.png")
	if err != nil {
		log.Println("Fehler beim Laden des Server-Icons:", err)
		return ""
	}
	encoded := base64.StdEncoding.EncodeToString(data)
	return "data:image/png;base64," + encoded
}

func handleConnectionB(conn net.Conn, icon string) {
	defer conn.Close()

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}
	packet := buf[:n]

	if len(packet) < 2 {
		return
	}

	// Status request
	if packet[1] == 0x00 {
		handleStatusB(conn, icon)
		return
	}

	// Login start (Join-Versuch)
	if packet[1] == 0x00 && len(packet) > 2 {
		handleLoginB(conn)
	}
}

func handleStatusB(conn net.Conn, icon string) {
	resp := map[string]interface{}{
		"version": map[string]interface{}{
			"name":     "Any",
			"protocol": 999, // akzeptiert alle
		},
		"players": map[string]interface{}{
			"max":    1,
			"online": 0,
		},
		"description": map[string]interface{}{
			"text": motdB,
		},
	}

	if icon != "" {
		resp["favicon"] = icon
	}

	b, _ := json.Marshal(resp)
	var full bytes.Buffer
	writeVarIntB(&full, len(b)+1)
	full.WriteByte(0x00)
	full.Write(b)

	conn.Write(full.Bytes())

	// Antwort auf Ping (Time)
	timeBuf := make([]byte, 8)
	conn.Read(timeBuf)
	conn.Write(timeBuf)
}

func handleLoginB(conn net.Conn) {
	var full bytes.Buffer
	msg := map[string]interface{}{
		"text": kickReasonB,
	}
	b, _ := json.Marshal(msg)

	writeVarIntB(&full, len(b)+1)
	full.WriteByte(0x00)
	full.Write(b)

	conn.Write(full.Bytes())
}

func writeVarIntB(buf *bytes.Buffer, value int) {
	for {
		temp := byte(value & 0x7F)
		value >>= 7
		if value != 0 {
			temp |= 0x80
		}
		buf.WriteByte(temp)
		if value == 0 {
			break
		}
	}
}
