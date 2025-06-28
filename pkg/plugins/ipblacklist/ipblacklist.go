package ipblacklist

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"time"

	"github.com/go-logr/logr"
	"github.com/robinbraemer/event"
	c "go.minekube.com/common/minecraft/component"
	"go.minekube.com/gate/pkg/edition/java/proxy"
)

var Plugin = proxy.Plugin{
	Name: "VPNCheck",
	Init: func(ctx context.Context, p *proxy.Proxy) error {
		log := logr.FromContextOrDiscard(ctx)
		log.Info("VPNCheck Plugin wird initialisiert...")
		
		plugin := &vpnCheckPlugin{
			log:          log,
			blockMessage: "VPN-Verbindungen sind nicht erlaubt auf diesem Server.",
			apiURL:       "https://vpn.otp.cx/check?ip=",
		}
		
		// Event-Handler registrieren mit höchster Priorität (0)
		event.Subscribe(p.Event(), 0, func(e event.Event) {
			plugin.handleEvent(e)
		})
		
		log.Info("VPNCheck Plugin erfolgreich initialisiert.")
		return nil
	},
}

type vpnCheckPlugin struct {
	log          logr.Logger
	blockMessage string
	apiURL       string
}

type vpnCheckResponse struct {
	IP      string `json:"ip"`
	IsVPN   bool   `json:"isVPN"`
	Details any    `json:"details"`
}

func (p *vpnCheckPlugin) handleEvent(e event.Event) {
	var ipAddr string
	var playerName string
	var disconnect func(c.Component)

	// IP-Adresse und Verbindung aus Event extrahieren
	switch eventType := e.(type) {
	case *proxy.LoginEvent:
		if player := eventType.Player(); player != nil {
			ipAddr = extractIP(player.RemoteAddr())
			playerName = player.Username()
			disconnect = player.Disconnect
		}
	default:
		// Versuche andere Event-Typen zu handhaben
		ipAddr = tryGetRemoteAddr(e)
		playerName = tryGetPlayerName(e)
	}

	if ipAddr == "" {
		return
	}

	// Lokale und private IPs nicht blockieren
	ip := net.ParseIP(ipAddr)
	if ip == nil || isPrivateIP(ip) {
		return
	}

	// VPN-Check durchführen
	isVPN, err := p.checkVPN(ipAddr)
	if err != nil {
		p.log.Error(err, "Fehler beim Prüfen der IP", "ip", ipAddr, "player", playerName)
		return
	}

	if isVPN {
		p.log.Info("VPN-Verbindung blockiert", "ip", ipAddr, "player", playerName)

		// Robuste Disconnect-Logik mit mehreren Fallback-Methoden
		
		// Methode 1: Verwende die Standard-Disconnect-Funktion wenn verfügbar
		if disconnect != nil {
			disconnect(&c.Text{Content: p.blockMessage})
			return
		}

		// Methode 2: Verwende tryDisconnect für andere Event-Typen
		if tryDisconnect(e, &c.Text{Content: p.blockMessage}) {
			return
		}

		// Fallback: Log, dass keine Disconnect-Methode verfügbar ist
		p.log.Info("Keine Disconnect-Methode verfügbar", "ip", ipAddr, "player", playerName)
	} else {
		p.log.V(1).Info("Verbindung erlaubt", "ip", ipAddr, "player", playerName)
	}
}

func (p *vpnCheckPlugin) checkVPN(ip string) (bool, error) {
	url := p.apiURL + ip
	
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, nil // Bei HTTP-Fehlern nicht blockieren
	}

	var result vpnCheckResponse
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return false, err
	}

	return result.IsVPN, nil
}

// Hilfsfunktionen

func extractIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}

	var ipStr string
	switch v := addr.(type) {
	case *net.TCPAddr:
		ipStr = v.IP.String()
	case *net.UDPAddr:
		ipStr = v.IP.String()
	default:
		addrStr := addr.String()
		host, _, err := net.SplitHostPort(addrStr)
		if err != nil {
			ipStr = addrStr
		} else {
			ipStr = host
		}
	}

	if net.ParseIP(ipStr) != nil {
		return ipStr
	}
	return ""
}

func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate()
}

func tryGetRemoteAddr(e interface{}) string {
	type remoteAddressProvider interface {
		RemoteAddr() net.Addr
	}
	if provider, ok := e.(remoteAddressProvider); ok {
		return extractIP(provider.RemoteAddr())
	}

	type connectionProvider interface {
		Connection() interface{ RemoteAddr() net.Addr }
	}
	if provider, ok := e.(connectionProvider); ok {
		if conn := provider.Connection(); conn != nil {
			return extractIP(conn.RemoteAddr())
		}
	}

	type initialConnectionProvider interface {
		InitialConnection() interface{ RemoteAddr() net.Addr }
	}
	if provider, ok := e.(initialConnectionProvider); ok {
		if conn := provider.InitialConnection(); conn != nil {
			return extractIP(conn.RemoteAddr())
		}
	}

	return ""
}

func tryGetPlayerName(e interface{}) string {
	type playerProvider interface {
		Player() interface{ Username() string }
	}
	if provider, ok := e.(playerProvider); ok {
		if player := provider.Player(); player != nil {
			return player.Username()
		}
	}

	type usernameProvider interface {
		Username() string
	}
	if provider, ok := e.(usernameProvider); ok {
		return provider.Username()
	}

	return "unbekannt"
}

func tryDisconnect(e interface{}, reason c.Component) bool {
	// 1. Versuche direkt die Disconnect-Methode aufzurufen
	type disconnector interface {
		Disconnect(c.Component)
	}
	if d, ok := e.(disconnector); ok {
		d.Disconnect(reason)
		return true
	}

	// 2. Versuche über Connection/InitialConnection
	type connectionProvider interface {
		Connection() interface{ Disconnect(c.Component) }
	}
	if provider, ok := e.(connectionProvider); ok {
		if conn := provider.Connection(); conn != nil {
			conn.Disconnect(reason)
			return true
		}
	}

	type initialConnectionProvider interface {
		InitialConnection() interface{ Disconnect(c.Component) }
	}
	if provider, ok := e.(initialConnectionProvider); ok {
		if conn := provider.InitialConnection(); conn != nil {
			conn.Disconnect(reason)
			return true
		}
	}

	// 3. Versuche über Player-Methode
	type playerProvider interface {
		Player() interface{ Disconnect(c.Component) }
	}
	if provider, ok := e.(playerProvider); ok {
		if player := provider.Player(); player != nil {
			player.Disconnect(reason)
			return true
		}
	}
	
	return false
}
