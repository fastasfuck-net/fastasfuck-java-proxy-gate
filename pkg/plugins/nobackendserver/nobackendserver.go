package nobackendserver

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
)

const (
	port       = 25566
	motd       = "§aMini-Server §7» §eNur Ping & Kick"
	kickReason = "§cDu wurdest gekickt!"
)

func main() {
	addr := fmt.Sprintf(":%d", port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Fehler beim Starten: %v", err)
	}
	defer listener.Close()

	log.Printf("Fake-Minecraft-Server läuft auf %s", addr)

	icon := loadServerIcon()

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleConnection(conn, icon)
	}
}

func loadServerIcon() string {
	data, err := ioutil.ReadFile("server-icon.png")
	if err != nil {
		log.Println("Hinweis: Keine server-icon.png gefunden.")
		return ""
	}
	encoded := base64.StdEncoding.EncodeToString(data)
	return "data:image/png;base64," + encoded
}

func handleConnection(conn net.Conn, icon string) {
	defer conn.Close()
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}

	packet := bytes.NewBuffer(buf[:n])
	_, _ = readVarInt(packet)       // Packet length
	packetID, _ := readVarInt(packet)

	if packetID == 0x00 { // Handshake
		_, _ = readVarInt(packet)        // Protocol version
		_ = readString(packet)           // Server address
		_, _ = readUnsignedShort(packet) // Port
		nextState, _ := readVarInt(packet)
		if nextState == 1 {
			handleStatus(conn, icon)
		} else if nextState == 2 {
			handleLogin(conn)
		}
	}
}

func handleStatus(conn net.Conn, icon string) {
	status := map[string]interface{}{
		"version": map[string]interface{}{
			"name":     "§cUnknown Version",
			"protocol": -1,
		},
		"players": map[string]interface{}{
			"max":    0,
			"online": 0,
		},
		"description": map[string]interface{}{
			"text": motd,
		},
	}
	if icon != "" {
		status["favicon"] = icon
	}

	data, _ := json.Marshal(status)
	sendPacket(conn, 0x00, data)

	// Antwort auf Ping
	buf := make([]byte, 512)
	conn.Read(buf)
	sendPacket(conn, 0x01, buf[3:]) // Pong-Paket mit gleichem Payload
}

func handleLogin(conn net.Conn) {
	// Sofortiger Kick beim Join
	msg := map[string]string{"text": kickReason}
	data, _ := json.Marshal(msg)
	sendPacket(conn, 0x00, data)
}

func sendPacket(conn net.Conn, packetID byte, data []byte) {
	packet := &bytes.Buffer{}
	writeVarInt(packet, int(packetID))
	packet.Write(data)

	full := &bytes.Buffer{}
	writeVarInt(full, packet.Len())
	full.Write(packet.Bytes())

	conn.Write(full.Bytes())
}

// --- Hilfsfunktionen für das Minecraft-Protokoll ---

func readVarInt(buf *bytes.Buffer) (int, error) {
	var num int
	var shift uint
	for {
		b, err := buf.ReadByte()
		if err != nil {
			return 0, err
		}
		num |= int(b&0x7F) << shift
		if b&0x80 == 0 {
			break
		}
		shift += 7
	}
	return num, nil
}

func readUnsignedShort(buf *bytes.Buffer) (uint16, error) {
	b := make([]byte, 2)
	if _, err := buf.Read(b); err != nil {
		return 0, err
	}
	return uint16(b[0])<<8 | uint16(b[1]), nil
}

func readString(buf *bytes.Buffer) string {
	length, _ := readVarInt(buf)
	b := make([]byte, length)
	buf.Read(b)
	return string(b)
}

func writeVarInt(buf *bytes.Buffer, value int) {
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
