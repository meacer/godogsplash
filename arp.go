package main

import (
	"bufio"
	"os"
	"strings"
)

// Taken from https://github.com/mostlygeek/arp/blob/master/arp_linux.go
func arp_get(req_ip string) string {
	const (
		f_IPAddr int = iota
		f_HWType
		f_Flags
		f_HWAddr
		f_Mask
		f_Device
	)
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		panic(err)
	}

	defer f.Close()

	s := bufio.NewScanner(f)
	s.Scan() // skip the field descriptions

	for s.Scan() {
		fields := strings.Fields(s.Text())
		if req_ip == fields[f_IPAddr] {
			return fields[f_HWAddr]
		}
	}
	return ""
}
