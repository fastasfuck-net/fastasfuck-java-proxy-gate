package lite

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/go-logr/logr"
	"go.minekube.com/gate/pkg/edition/java/lite/blacklist"
	"go.minekube.com/gate/pkg/edition/java/lite/config"
	"go.minekube.com/gate/pkg/edition/java/netmc"
	"go.minekube.com/gate/pkg/edition/java/proto/codec"
	"go.minekube.com/gate/pkg/edition/java/proto/packet"
	"go.minekube.com/gate/pkg/edition/java/proto/state"
	"go.minekube.com/gate/pkg/edition/java/proto/util"
	"go.minekube.com/gate/pkg/gate/proto"
	"go.minekube.com/gate/pkg/util/errs"
	"go.minekube.com/gate/pkg/util/netutil"
)

// PRAKTISCHER ANSATZ: Modifikation der emptyReadBuff Funktion
// um Spielernamen zu extrahieren bevor das Backend-Forwarding beginnt

func emptyReadBuffWithPlayerName(src netmc.MinecraftConn, dst net.Conn, 
	log logr.Logger, protocol proto.Protocol, handshake *packet.Handshake) (string, error) {
	
	var playerName string
	
	buf, ok := src.(interface{ ReadBuffered() ([]byte, error) })
	if ok {
		b, err := buf.ReadBuffered()
		if err != nil {
			return "", fmt.Errorf("failed to read buffered bytes: %w", err)
		}
		
		if len(b) != 0 {
			// Versuche Spielername zu extrahieren bevor wir weiterleiten
			if handshake.NextState == 2 { // Login state
				if name, loginPacket, err := extractPlayerNameFromBytes(b, protocol); err == nil {
					playerName = name
					log.Info("Extracted player name", "playerName", playerName)
					
					// Schreibe das Login-Paket an das Backend
					_, err = dst.Write(loginPacket)
					if err != nil {
						return playerName, fmt.Errorf("failed to write login packet: %w", err)
					}
					
					// Schreibe den Rest des Buffers (falls vorhanden)
					remainingData := b[len(loginPacket):]
					if len(remainingData) > 0 {
						_, err = dst.Write(remainingData)
						if err != nil {
							return playerName, fmt.Errorf("failed to write remaining data: %w", err)
						}
					}
				} else {
					// Fallback: Schreibe alles weiter ohne Namen-Extraktion
					log.V(1).Info("Could not extract player name", "error", err)
					_, err = dst.Write(b)
					if err != nil {
						return "", fmt.Errorf("failed to write buffered bytes: %w", err)
					}
				}
			} else {
				// Nicht-Login Pakete: Einfach weiterleiten
				_, err = dst.Write(b)
				if err != nil {
					return "", fmt.Errorf("failed to write buffered bytes: %w", err)
				}
			}
		}
	}
	return playerName, nil
}

// Extrahiert Spielername und gibt das komplette Login-Paket zurück
func extractPlayerNameFromBytes(data []byte, protocol proto.Protocol) (string, []byte, error) {
	if len(data) < 3 {
		return "", nil, fmt.Errorf("insufficient data")
	}
	
	reader := bytes.NewReader(data)
	originalPos := reader.Len()
	
	// Lese Packet Length (VarInt)
	packetLen, err := util.ReadVarInt(reader)
	if err != nil {
		return "", nil, err
	}
	
	if packetLen <= 0 || packetLen > len(data) {
		return "", nil, fmt.Errorf("invalid packet length: %d", packetLen)
	}
	
	// Berechne Start-Position des Pakets
	startPos := originalPos - reader.Len()
	
	// Lese Packet ID
	packetID, err := util.ReadVarInt(reader)
	if err != nil {
		return "", nil, err
	}
	
	// Prüfe ob es Login Start ist (ID 0x00 im Login state)
	if packetID != 0x00 {
		return "", nil, fmt.Errorf("not a login start packet, got ID: 0x%02x", packetID)
	}
	
	// Lese Username
	username, err := util.ReadStringMax(reader, 16)
	if err != nil {
		return "", nil, err
	}
	
	// Extrahiere das komplette Paket
	packetEndPos := startPos + int(util.VarIntBytes(packetLen)) + int(packetLen)
	if packetEndPos > len(data) {
		return "", nil, fmt.Errorf("packet extends beyond data")
	}
	
	loginPacket := data[startPos:packetEndPos]
	
	return username, loginPacket, nil
}

// Modifizierte Forward-Funktion
func ForwardWithPlayerName(
	dialTimeout time.Duration,
	routes []config.Route,
	log logr.Logger,
	client netmc.MinecraftConn,
	handshake *packet.Handshake,
	pc *proto.PacketContext,
) {
	defer func() { _ = client.Close() }()

	log, src, route, nextBackend, err := findRoute(routes, log, client, handshake)
	if err != nil {
		errs.V(log, err).Info("failed to find route", "error", err)
		return
	}

	// Setze den Logger für das Blacklist-Paket
	blacklist.SetLogger(log)

	// Extrahiere die Client-IP und prüfe auf Blacklist
	clientIP, _, err := net.SplitHostPort(src.RemoteAddr().String())
	if err == nil && blacklist.CheckIP(clientIP) {
		log.Info("Connection rejected - IP is blacklisted", "ip", clientIP)
		return
	}

	// Find a backend to dial successfully.
	log, dst, err := tryBackends(nextBackend, func(log logr.Logger, backendAddr string) (logr.Logger, net.Conn, error) {
		conn, err := dialRoute(client.Context(), dialTimeout, src.RemoteAddr(), route, backendAddr, handshake, pc, false)
		return log, conn, err
	})
	if err != nil {
		return
	}
	defer func() { _ = dst.Close() }()

	// MODIFIZIERT: Verwende die neue Funktion mit Spielername-Extraktion
	playerName, err := emptyReadBuffWithPlayerName(client, dst, log, proto.Protocol(handshake.ProtocolVersion), handshake)
	if err != nil {
		errs.V(log, err).Info("failed to process client buffer", "error", err)
		return
	}

	// Füge Spielername zum Logger hinzu falls verfügbar
	if playerName != "" {
		log = log.WithValues("playerName", playerName)
		
		// Prüfe Spielername-Blacklist
		if isPlayerBlacklisted(playerName) {
			log.Info("Connection rejected - player is blacklisted", "playerName", playerName)
			return
		}
	}

	log.Info("forwarding connection", 
		"backendAddr", netutil.Host(dst.RemoteAddr()),
		"playerName", playerName)
	
	pipe(log, src, dst)
}

// Einfache Spielername-Blacklist
func isPlayerBlacklisted(playerName string) bool {
	blacklistedPlayers := []string{
		"griefer123", 
		"hacker456", 
		"spammer789",
		// Füge hier weitere Namen hinzu
	}
	
	for _, blocked := range blacklistedPlayers {
		if playerName == blocked {
			return true
		}
	}
	return false
}

// Hilfsfunktion um VarInt Byte-Länge zu berechnen
func varIntBytes(value int) int {
	if value == 0 {
		return 1
	}
	bytes := 0
	for value != 0 {
		value >>>= 7
		bytes++
	}
	return bytes
}

// ALTERNATIVE: Einfacher Player-Logger (falls Extraktion fehlschlägt)
// Loggt nur das Factum dass ein Login-Versuch stattfindet
func logPlayerAttempt(log logr.Logger, handshake *packet.Handshake, clientAddr net.Addr) {
	if handshake.NextState == 2 { // Login state
		log.Info("Player login attempt detected", 
			"clientAddr", netutil.Host(clientAddr),
			"protocol", proto.Protocol(handshake.ProtocolVersion).String(),
			"virtualHost", handshake.ServerAddress)
	}
}
