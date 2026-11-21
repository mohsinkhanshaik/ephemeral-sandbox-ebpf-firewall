package firewall

import (
	"fmt"
	"time"
)

// Event is a firewall decision reported by the kernel.
type Event struct {
	Time    time.Time `json:"time"`
	Hook    string    `json:"hook"`
	Verdict string    `json:"verdict"`
	Proto   string    `json:"proto"`
	Dst     string    `json:"dst"`
}

// Stats are cumulative counters for one sandbox.
type Stats struct {
	ConnAllowed uint64 `json:"conn_allowed"`
	ConnDenied  uint64 `json:"conn_denied"`
	PktsDropped uint64 `json:"pkts_dropped"`
}

func hookName(h uint8) string {
	switch h {
	case 1:
		return "connect4"
	case 2:
		return "sendmsg4"
	case 3:
		return "connect6"
	case 4:
		return "sendmsg6"
	case 5:
		return "egress"
	}
	return fmt.Sprintf("hook%d", h)
}

func protoName(p uint8) string {
	switch p {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 0:
		return "ip"
	}
	return fmt.Sprintf("proto%d", p)
}

func verdictName(v uint8) string {
	if v == 1 {
		return "allow"
	}
	return "deny"
}
