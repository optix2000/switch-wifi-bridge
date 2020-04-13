package main

import "os"
import "github.com/wafuu-chan/switch-wifi-bridge/cmd"

func main() {
	err := cmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
