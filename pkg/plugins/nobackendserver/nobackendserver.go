package nobackendserver

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"log"
	"net"
	"os"
)

const (
	portb       = 25566
	motdb       = "§aMini-Server §7» §eNur Ping & Kick"
	kickReasonb = "§cDu wurdest gekickt!"
)

func main() {
	listenerb, errb := net.Listen("tcp", ":25566")
	if errb != nil {
		log.Fatalf("Fehler beim Starten: %v", errb)
	}
	log.Println("Fake-Server läuft auf Port 25566...")

	iconb := loadServerIconb()

	for {
		connb, errb := listenerb.Accept()
		if errb != nil {
			log.Printf("Verbindungsfehler: %v", errb)
			continue
		}
		go handleConnectionb(connb, iconb)
	}
}

func loadServerIconb() string {
	datab, errb := os.ReadFile("server-icon.png")
	if errb != nil {
		log.Println("Hinweis: server-icon.png nicht gefunden:", errb)
		return ""
	}
	encodedb := base64.StdEncoding.EncodeToString(datab)
	return "data:image/png;base64," + encodedb
}

func handleConnectionb(connb net.Conn, iconb string) {
	defer connb.Close()

	bufb := make([]byte, 512)
	_, errb := connb.Read(bufb)
	if errb != nil {
		log.Printf("Fehler beim Lesen: %v", errb)
		return
	}

	packetb := bytes.NewBuffer(bufb)
	_, _ = readVarIntb(packetb)     // packet length
	packetIDb, _ := readVarIntb(packetb) // packet id

	if packetIDb == 0x00 { // Handshake
		_, _ = readVarIntb(packetb) // protocol version
		_ = readStringb(packetb)   // server address
		_, _ = readUnsignedShortb(packetb)
		nextStateb, _ := readVarIntb(packetb)

		// Status
		if nextStateb == 1 {
			handleStatusb(connb, iconb)
		} else if nextStateb == 2 {
			handleLoginb(connb)
		}
	}
}

func handleStatusb(connb net.Conn, iconb string) {
	bufb := make([]byte, 512)
	_, errb := connb.Read(bufb)
	if errb != nil {
		log.Printf("Fehler beim Lesen (Status): %v", errb)
		return
	}

	resp := map[string]interface{}{
		"version": map[string]interface{}{
			"name":     "1.20.1",
			"protocol": 763,
		},
		"players": map[string]interface{}{
			"max":    0,
			"online": 0,
		},
		"description": map[string]string{
			"text": motdb,
		},
	}
	if iconb != "" {
		resp["favicon"] = iconb
	}

	respJSONb, _ := json.Marshal(resp)
	respPacketb := new(bytes.Buffer)
	writeVarIntb(respPacketb, len(respJSONb))
	respPacketb.Write(respJSONb)

	sendPacketb(connb, 0x00, respPacketb.Bytes())

	// Ping zurücksenden
	connb.Read(bufb)
	connb.Write(bufb)
}

func handleLoginb(connb net.Conn) {
	bufb := new(bytes.Buffer)
	writeVarIntb(bufb, len(kickReasonb)+3)
	bufb.WriteByte(0x00) // packet id
	writeVarIntb(bufb, len(kickReasonb))
	bufb.WriteString(kickReasonb)

	connb.Write(bufb.Bytes())
}

func sendPacketb(connb net.Conn, packetIDb byte, datab []byte) {
	fullb := new(bytes.Buffer)
	packetb := new(bytes.Buffer)

	packetb.WriteByte(packetIDb)
	packetb.Write(datab)

	writeVarIntb(fullb, packetb.Len())
	fullb.Write(packetb.Bytes())

	connb.Write(fullb.Bytes())
}

func readVarIntb(bufb *bytes.Buffer) (int, error) {
	var valueb int
	var shiftb uint
	for {
		bb, errb := bufb.ReadByte()
		if errb != nil {
			return 0, errb
		}
		valueb |= int(bb&0x7F) << shiftb
		if bb&0x80 == 0 {
			break
		}
		shiftb += 7
	}
	return valueb, nil
}

func readUnsignedShortb(bufb *bytes.Buffer) (uint16, error) {
	var b [2]byte
	_, errb := bufb.Read(b[:])
	return binary.BigEndian.Uint16(b[:]), errb
}

func readStringb(bufb *bytes.Buffer) string {
	lengthb, _ := readVarIntb(bufb)
	sb := make([]byte, lengthb)
	_, _ = bufb.Read(sb)
	return string(sb)
}

func writeVarIntb(bufb *bytes.Buffer, valueb int) {
	for {
		tempb := byte(valueb & 0x7F)
		valueb >>= 7
		if valueb != 0 {
			tempb |= 0x80
		}
		bufb.WriteByte(tempb)
		if valueb == 0 {
			break
		}
	}
}
