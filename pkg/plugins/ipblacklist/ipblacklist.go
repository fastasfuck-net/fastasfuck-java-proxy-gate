package ipblacklist

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"

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
	VPN bool `json:"vpn"`
}

func checkAndDisconnect(ip string, login *proxy.LoginEvent, log logr.Logger) {
	if ip == "" {
		return
	}

	url := fmt.Sprintf("https://vpn.otp.cx/check?ip=%s", ip)
	resp, err := http.Get(url)
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

	if data.isVPN {
		log.Info("Verbindung von VPN blockiert", "ip", ip)
		login.Player().Disconnect(&component.Text{
			Content: "Verbindungen über VPN sind nicht erlaubt.",
		})
	}
}
