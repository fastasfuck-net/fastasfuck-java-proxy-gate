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
		log.Info("VPN Blacklist Plugin initializing...")

		event.Subscribe(p.Event(), 0, func(e event.Event) {
			if login, ok := e.(*proxy.LoginEvent); ok {
				ip := extractIP(login.Player().RemoteAddr())
				go checkAndDisconnect(ip, login, log)
			}
		})

		log.Info("VPN Blacklist Plugin successfully activated")
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
	IsVPN bool `json:"isVPN"`  // Corrected: API delivers "isVPN", not "vpn"
}

func checkAndDisconnect(ip string, login *proxy.LoginEvent, log logr.Logger) {
	if ip == "" {
		return
	}

	// Skip checking local/private IPs
	if isLocalIP(ip) {
		return
	}

	log.Info("Checking IP for VPN", "ip", ip)

	// HTTP-Client mit Timeout
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	url := fmt.Sprintf("https://vpn.otp.cx/check?ip=%s", ip)
	resp, err := client.Get(url)
	if err != nil {
		log.Error(err, "Error fetching VPN-Check-API", "ip", ip)
		return
	}
	defer resp.Body.Close()

	var data vpnResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		log.Error(err, "Error parsing response", "ip", ip)
		return
	}

	if data.IsVPN {  // Corrected: data.IsVPN instead of data.isVPN
		log.Info("Connection from VPN blocked", "ip", ip)
		login.Player().Disconnect(&component.Text{
			Content: "§c§lVPN/Proxy Detected §7- §4Connection Blocked\n\n§7Your connection was flagged as a §cVPN §7or §cProxy.\n\n§7Not using one? Appeal on Discord:\n§9dc.otp.cx",
		})
	} else {
		log.Info("IP allowed", "ip", ip)
	}
}

// Helper function to detect local/private IPs
func isLocalIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	return parsedIP.IsLoopback() || parsedIP.IsPrivate()
}
