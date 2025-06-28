package main

import (
	"go.minekube.com/gate/cmd/gate"
	"go.minekube.com/gate/pkg/edition/java/proxy"
	"go.minekube.com/gate/pkg/plugins/ipblacklist"
	"go.minekube.com/gate/pkg/plugins/configdownloader"
	"go.minekube.com/gate/pkg/plugins/antivpn"
	"go.minekube.com/gate/pkg/plugins/nobackendserver"
)

func main() {
	// Register plugins
	proxy.Plugins = append(proxy.Plugins,
		ipblacklist.Plugin,
		configdownloader.Plugin,
		antivpn.Plugin,
	)

	// Start Gate proxy
	gate.Execute()
	nobackendserver.StartServer()
}
