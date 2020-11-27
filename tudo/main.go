/**
 * Written by Vy Nguyen (2018)
 */
package main

import (
	"os"

	"github.com/ethereum/go-ethereum/tudo/proxy"
)

func main() {
	self := proxy.NewTdApp()
	os.Args = []string{os.Args[0], "--verbosity", "3", "--basedir", ""}
	self.Run(os.Args, "")
}
