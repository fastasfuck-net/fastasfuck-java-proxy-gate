package main

import (
	"go.minekube.com/gate/cmd/gate"
	"go.minekube.com/gate/pkg/edition/java/proxy"
	"go.minekube.com/gate/pkg/plugins/ipblacklist"
)

func main() {
	// Plugin registrieren
	proxy.Plugins = append(proxy.Plugins,
		ipblacklist.Plugin,
	)
	
	// Gate starten
	gate.Execute()
}
