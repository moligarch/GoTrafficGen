package internal

import (
	"fmt"
	"net"
)

// GetInterfaceIPv4 returns the first IPv4 address of iface.
func GetInterfaceIPv4(iface string) (net.IP, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok {
			if ip4 := ipnet.IP.To4(); ip4 != nil {
				return ip4, nil
			}
		}
	}
	return nil, fmt.Errorf("no IPv4 on interface %s", iface)
}
