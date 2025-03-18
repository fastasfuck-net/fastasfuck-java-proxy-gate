package main

import (
	"go.minekube.com/gate/cmd/gate"
	"go.minekube.com/gate/pkg/edition/java/proxy"
	"go.minekube.com/gate/pkg/plugins/ipblacklist"
)

func init() {
	// Plugin vor dem Start registrieren
	proxy.Plugins = append(proxy.Plugins, ipblacklist.Plugin)
}

func main() {
	// Gate starten
	gate.Execute()
}
