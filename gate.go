package main

import (
	"go.minekube.com/gate/cmd/gate"
	"go.minekube.com/gate/pkg/edition/java/proxy"
	"./plugins/ipblacklist" // lokaler Import deines Plugins
)

func main() {
	// Plugin registrieren
	proxy.Plugins = append(proxy.Plugins,
		ipblacklist.Plugin,
	)
	
	// Gate starten
	gate.Execute()
}
