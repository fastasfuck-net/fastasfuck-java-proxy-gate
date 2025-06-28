package ipblacklist

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/go-logr/logr"
	"github.com/robinbraemer/event"
	"go.minekube.com/common/minecraft/component"
	"go.minekube.com/gate/pkg/edition/java/proxy"
)

var Plugin = proxy.Plugin{
	Name: "IPBlacklistVPNCheck",
	Init: func(ctx context.Context, p *proxy.Proxy) error {
		log := logr.FromContextOrDiscard(ctx)
		log.Info("VPN Blacklist Plugin wird initialisiert...")

		event.Subscribe(p.Event(), 0, func(e event.Event) {
			if login, ok := e.(*proxy.LoginEvent); ok {
				ip := extractIP(login.Player().RemoteAddr())
				go checkAndDisconnect(ip, login, log)
			}
		})

		log.Info("VPN Blacklist Plugin erfolgreich aktiviert")
		return nil
	},
}

func extractIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

type vpnResponse struct {
	IsVPN bool `json:"isVPN"`  // Korrigiert: API liefert "isVPN", nicht "vpn"
}

func checkAndDisconnect(ip string, login *proxy.LoginEvent, log logr.Logger) {
	if ip == "" {
		return
	}

	// Lokale/private IPs nicht prüfen
	if isLocalIP(ip) {
		return
	}

	log.Info("Prüfe IP auf VPN", "ip", ip)

	// HTTP-Client mit Timeout
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	url := fmt.Sprintf("https://vpn.otp.cx/check?ip=%s", ip)
	resp, err := client.Get(url)
	if err != nil {
		log.Error(err, "Fehler beim Abrufen der VPN-Check-API", "ip", ip)
		return
	}
	defer resp.Body.Close()

	var data vpnResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		log.Error(err, "Fehler beim Parsen der Antwort", "ip", ip)
		return
	}

	if data.IsVPN {  // Korrigiert: data.IsVPN statt data.isVPN
		log.Info("Verbindung von VPN blockiert", "ip", ip)
		login.Player().Disconnect(&component.Text{
			Content: "Verbindungen über VPN sind nicht erlaubt.",
		})
	} else {
		log.Info("IP erlaubt", "ip", ip)
	}
}

// Hilfsfunktion um lokale/private IPs zu erkennen
func isLocalIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	return parsedIP.IsLoopback() || parsedIP.IsPrivate()
}
