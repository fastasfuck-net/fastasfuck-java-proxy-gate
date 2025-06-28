package ipblacklist

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"

	"go.minekube.com/gate/pkg/gate"
	"go.minekube.com/gate/pkg/gate/plugin"
	"go.minekube.com/gate/pkg/edition/java"
)

// Struktur zum Parsen der JSON-Antwort
type vpnResponse struct {
	IP      string `json:"ip"`
	IsVPN   bool   `json:"isVPN"`
	Details struct {
		ASN      string `json:"asn"`
		ASNOrg   string `json:"asnOrg"`
		ISP      string `json:"isp"`
		Hostname string `json:"hostname"`
		ASNMatch bool   `json:"asnMatch"`
		ISPMatch bool   `json:"ispMatch"`
		IPListed bool   `json:"ipListed"`
	} `json:"details"`
}

// Plugin-Struktur
type Plugin struct {
	plugin.Instance
}

// Registrierung beim Gate-Plugin-System
func NewPlugin(p *plugin.Registration) error {
	return plugin.Init(p, &Plugin{})
}

// Plugin-Initialisierung
func (p *Plugin) Init(ctx *plugin.Context, g *gate.Gate) error {
	log.Println("[ipblacklist] Plugin aktiviert.")

	// Spieler-Login-Event abonnieren
	g.EventBus().Subscribe(ctx, func(e *java.LoginEvent) {
		go func() {
			addr := e.Connection().RemoteAddr()
			ip, _, err := net.SplitHostPort(addr.String())
			if err != nil {
				log.Printf("[ipblacklist] Fehler beim Parsen der IP: %v", err)
				return
			}

			resp, err := checkVPN(ip)
			if err != nil {
				log.Printf("[ipblacklist] Fehler beim VPN-Check: %v", err)
				return
			}

			if resp.IsVPN {
				log.Printf("[ipblacklist] Verbindung von VPN (%s) blockiert.", ip)
				e.Connection().Disconnect("Verbindung über VPN nicht erlaubt.")
			} else {
				log.Printf("[ipblacklist] Verbindung von %s erlaubt (kein VPN).", ip)
			}
		}()
	})

	return nil
}

// VPN-Prüfung über die otp.cx-API
func checkVPN(ip string) (*vpnResponse, error) {
	url := fmt.Sprintf("https://vpn.otp.cx/check?ip=%s", ip)

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("HTTP-Fehler: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Fehler beim Lesen des API-Response: %w", err)
	}

	var data vpnResponse
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("Fehler beim Parsen des JSON: %w", err)
	}

	return &data, nil
}
