package main

import (
	"log"

	"github.com/0la-mide/recon-cli/cmd"
)

func main() {
	log.SetOutput(nil) // suppress http client noise
	cmd.Execute()
}
