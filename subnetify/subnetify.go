package main

import (
	"fmt"
	"net"
	"os"
)

func main() {
	// Get a list of all network interfaces on the device (Wi-Fi, Cellular, Ethernet)
	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Printf("Error fetching network interfaces: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("=== Active Network Subnets ===")

	for _, iface := range interfaces {
		// Skip interfaces that are down or loopback (127.0.0.1)
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		// Get all addresses assigned to the current active interface
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			// Cast the address to a net.IPNet type to extract the IP and Subnet Mask
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			// We want to focus on IPv4 addresses for local network mapping
			ipv4 := ipNet.IP.To4()
			if ipv4 != nil {
				// ipNet.String() automatically formats the output into CIDR notation (e.g., 192.168.8.4/24)
				fmt.Printf("Interface: %-10s | Local IP: %-15s | Subnet Range: %s\n", 
					iface.Name, ipv4.String(), ipNet.String())
			}
		}
	}
}
