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

		event.Subscribe(p.Event(), 0, plugin.handleEvent)
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
	Details any    `json:"details"` // optional, falls du es loggen möchtest
}

func (p *vpnCheckPlugin) handleEvent(e event.Event) {
	loginEvent, ok := e.(*proxy.LoginEvent)
	if !ok {
		return
	}

	player := loginEvent.Player()
	ip := extractIP(player.RemoteAddr())

	if ip == "" || isPrivateIP(net.ParseIP(ip)) {
		return
	}

	// Anfrage an vpn.otp.cx
	isVPN, err := p.checkVPN(ip)
	if err != nil {
		p.log.Error(err, "Fehler beim Prüfen der IP", "ip", ip)
		return
	}

	if isVPN {
		p.log.Info("VPN blockiert", "ip", ip, "name", player.Username())
		player.Disconnect(&c.Text{Content: p.blockMessage})
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

	var result vpnCheckResponse
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return false, err
	}

	return result.IsVPN, nil
}

func extractIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	switch v := addr.(type) {
	case *net.TCPAddr:
		return v.IP.String()
	case *net.UDPAddr:
		return v.IP.String()
	default:
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return addr.String()
		}
		return host
	}
}

func isPrivateIP(ip net.IP) bool {
	privateBlocks := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"fc00::/7",
		"fe80::/10",
	}
	for _, block := range privateBlocks {
		_, cidr, _ := net.ParseCIDR(block)
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}
