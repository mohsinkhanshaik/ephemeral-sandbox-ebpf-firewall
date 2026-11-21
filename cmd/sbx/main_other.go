//go:build !linux

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "sbx needs Linux (cgroup v2 + eBPF). Try it in a Linux VM (kernel 5.15+).")
	os.Exit(1)
}
