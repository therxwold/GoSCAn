package app

import (
	"fmt"
	"os"
)

// Version is the current GoSCAn version.
const Version string = "v0.1.0"

// Run starts GoSCAn.
func Run() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-v", "--version", "version":
			fmt.Printf("goscan %s\n", Version)
			return
		}
	}
	fmt.Println("GoSCAn - Go dependency vulnerability scanner")
}
