package nobackendserver

import (
	"context"
	"log"
	"net"

	"go.minekube.com/gate/pkg/edition/java"
)

var Plugin = java.PluginFunc(startFakeServer)

func startFakeServer(ctx context.Context, srv *java.Server) error {
	go func() {
		// Hier dein Server-Code
		listener, err := net.Listen("tcp", ":25566")
		if err != nil {
			log.Println("Fehler beim Starten des Fake-Servers:", err)
			return
		}
		log.Println("Fake-Server läuft auf Port 25566...")

		icon := loadServerIcon()

		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Println("Verbindungsfehler:", err)
				continue
			}
			go handleConnection(conn, icon)
		}
	}()
	return nil
}
