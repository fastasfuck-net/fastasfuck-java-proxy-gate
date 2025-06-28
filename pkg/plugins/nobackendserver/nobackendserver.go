package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
)

// Server-Konfiguration
const (
	port       = 25566
	motd       = "§aMini-Server §7» §eNur Ping & Kick"
	kickReason = "§cDu wurdest gekickt!"
)

// Funktion zum Laden des Server-Icons (nur ein Platzhalter)
func loadServerIcon() string {
	// Hier kannst du das tatsächliche Server-Icon laden
	// Zum Beispiel: Dateisystem, DB, etc.
	return "data:image/png;base64,..."
}

// Hauptverbindungsbehandlung
func handleConnection(conn net.Conn, icon string) {
	defer conn.Close()

	// Hier sendest du ein MOTD und Icon
	fmt.Println("Neue Verbindung:", conn.RemoteAddr())

	// Sende Server-MOTD und Icon
	conn.Write([]byte(motd + "\n"))
	conn.Write([]byte(icon))

	// Kicke den Benutzer nach dem Joinen
	conn.Write([]byte(kickReason))
}

// Server-Startfunktion
func startServer() {
	// Server lauscht auf Port 25566
	listen, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("Fehler beim Starten des Servers: %v", err)
	}
	defer listen.Close()
	log.Printf("Server läuft auf Port %d...", port)

	// Verbindungsannahme und Handhabung
	for {
		conn, err := listen.Accept()
		if err != nil {
			log.Printf("Verbindungsfehler: %v", err)
			continue
		}

		// Lade Server-Icon
		icon := loadServerIcon()

		// Verarbeite die eingehende Verbindung
		go handleConnection(conn, icon)
	}
}

func main() {
	// Starte den Server
	startServer()
}
