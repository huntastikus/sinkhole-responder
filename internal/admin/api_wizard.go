package admin

import (
	"net"
	"net/http"
	"sort"
)

type lanIP struct {
	Addr   string `json:"addr"`
	Iface  string `json:"iface"`
	Family string `json:"family"`
}

func (s *Server) handleLANIP(w http.ResponseWriter, _ *http.Request) {
	interfaces, err := net.Interfaces()
	if err != nil {
		writeConfigError(w, http.StatusInternalServerError, "enumerate network interfaces")
		return
	}

	ips := make([]lanIP, 0)
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			writeConfigError(w, http.StatusInternalServerError, "enumerate network interface addresses")
			return
		}
		for _, address := range addresses {
			ip := addressIP(address)
			if ip == nil || !ip.IsGlobalUnicast() || ip.IsLinkLocalUnicast() || ip.IsLoopback() {
				continue
			}
			family := "ipv6"
			if ip.To4() != nil {
				family = "ipv4"
			}
			ips = append(ips, lanIP{Addr: ip.String(), Iface: iface.Name, Family: family})
		}
	}
	sort.Slice(ips, func(i, j int) bool {
		if ips[i].Family != ips[j].Family {
			return ips[i].Family == "ipv4"
		}
		if ips[i].Iface != ips[j].Iface {
			return ips[i].Iface < ips[j].Iface
		}
		return ips[i].Addr < ips[j].Addr
	})

	writeConfigJSON(w, http.StatusOK, map[string][]lanIP{"ips": ips})
}

func addressIP(address net.Addr) net.IP {
	switch value := address.(type) {
	case *net.IPNet:
		return value.IP
	case *net.IPAddr:
		return value.IP
	default:
		return nil
	}
}
