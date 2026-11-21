// Package policy parses egress allow rules and encodes them into the layout
// the eBPF LPM trie expects. It is pure Go and builds on any platform.
package policy

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Rule allows egress to an IPv4 prefix, optionally on a single port.
type Rule struct {
	Net  netip.Prefix
	Port uint16 // 0 = any port
}

func (r Rule) String() string {
	if r.Port == 0 {
		return r.Net.String() + ":*"
	}
	return r.Net.String() + ":" + strconv.Itoa(int(r.Port))
}

// Resolver looks up the addresses of a hostname.
type Resolver func(host string) ([]netip.Addr, error)

// SystemResolver resolves with the host's resolver.
func SystemResolver(host string) ([]netip.Addr, error) {
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if a, ok := netip.AddrFromSlice(ip); ok {
			out = append(out, a.Unmap())
		}
	}
	return out, nil
}

// Parse turns one --allow value into rules. Accepted forms:
//
//	1.1.1.1            single host, any port
//	1.1.1.1:443        single host, one port
//	10.0.0.0/8         prefix, any port
//	10.0.0.0/8:5432    prefix, one port
//	example.com:443    hostname, resolved once at sandbox start
func Parse(s string, resolve Resolver) ([]Rule, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty rule")
	}
	host, port, err := splitPort(s)
	if err != nil {
		return nil, fmt.Errorf("rule %q: %w", s, err)
	}

	if strings.Contains(host, "/") {
		p, err := netip.ParsePrefix(host)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", s, err)
		}
		if !p.Addr().Is4() {
			return nil, fmt.Errorf("rule %q: only IPv4 prefixes are supported", s)
		}
		return []Rule{{Net: p.Masked(), Port: port}}, nil
	}

	if a, err := netip.ParseAddr(host); err == nil {
		if !a.Is4() {
			return nil, fmt.Errorf("rule %q: only IPv4 addresses are supported", s)
		}
		return []Rule{{Net: netip.PrefixFrom(a, 32), Port: port}}, nil
	}

	if resolve == nil {
		return nil, fmt.Errorf("rule %q: hostnames need a resolver", s)
	}
	addrs, err := resolve(host)
	if err != nil {
		return nil, fmt.Errorf("rule %q: resolve: %w", s, err)
	}
	var rules []Rule
	seen := map[netip.Addr]bool{}
	for _, a := range addrs {
		a = a.Unmap()
		if !a.Is4() || seen[a] {
			continue
		}
		seen[a] = true
		rules = append(rules, Rule{Net: netip.PrefixFrom(a, 32), Port: port})
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("rule %q: no IPv4 addresses found", s)
	}
	return rules, nil
}

// splitPort splits "host[:port]". IPv6 literals are rejected by the caller.
func splitPort(s string) (string, uint16, error) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return s, 0, nil
	}
	if strings.Count(s, ":") > 1 {
		return "", 0, errors.New("IPv6 is not supported")
	}
	p := s[i+1:]
	if p == "*" {
		return s[:i], 0, nil
	}
	n, err := strconv.ParseUint(p, 10, 16)
	if err != nil || n == 0 {
		return "", 0, fmt.Errorf("invalid port %q", p)
	}
	return s[:i], uint16(n), nil
}

// Loopback allows all of 127.0.0.0/8.
func Loopback() Rule {
	return Rule{Net: netip.MustParsePrefix("127.0.0.0/8")}
}

// ParseResolvConf returns a port-53 rule for every IPv4 nameserver.
func ParseResolvConf(r io.Reader) ([]Rule, error) {
	var rules []Rule
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 || f[0] != "nameserver" {
			continue
		}
		a, err := netip.ParseAddr(f[1])
		if err != nil || !a.Is4() {
			continue
		}
		rules = append(rules, Rule{Net: netip.PrefixFrom(a, 32), Port: 53})
	}
	return rules, sc.Err()
}

// Key mirrors struct lpm_key in bpf/firewall.bpf.c.
type Key struct {
	Prefixlen uint32
	Port      uint16 // network byte order
	Addr      uint32 // network byte order
}

// Key encodes the rule for the LPM trie.
func (r Rule) Key() Key {
	return Key{
		Prefixlen: 32 + uint32(r.Net.Bits()),
		Port:      Htons(r.Port),
		Addr:      AddrToKernel(r.Net.Addr()),
	}
}

// Htons converts a host-order port to the value the kernel stores in memory.
func Htons(p uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], p)
	return binary.NativeEndian.Uint16(b[:])
}

// Ntohs is the inverse of Htons.
func Ntohs(p uint16) uint16 {
	var b [2]byte
	binary.NativeEndian.PutUint16(b[:], p)
	return binary.BigEndian.Uint16(b[:])
}

// AddrToKernel encodes an IPv4 address as a network-order uint32.
func AddrToKernel(a netip.Addr) uint32 {
	b := a.As4()
	return binary.NativeEndian.Uint32(b[:])
}

// AddrFromKernel decodes a network-order uint32 into an address.
func AddrFromKernel(v uint32) netip.Addr {
	var b [4]byte
	binary.NativeEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}
