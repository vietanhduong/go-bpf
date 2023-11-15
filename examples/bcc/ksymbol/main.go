package main

import (
	"log"
	"os"

	"github.com/vietanhduong/go-bpf/bcc"
)

func main() {
	ksyms, err := bcc.LoadProcKallsym()
	if err != nil {
		log.Printf("Failed to load Kallsyms: %v", err)
		os.Exit(1)
	}
	for _, sym := range ksyms {
		log.Println(sym.String())
	}
}
