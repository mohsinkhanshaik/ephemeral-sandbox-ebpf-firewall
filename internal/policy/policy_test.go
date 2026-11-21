package policy

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	fakeDNS := func(host string) ([]netip.Addr, error) {
		switch host {
		case "api.example.com":
			return []netip.Addr{
				netip.MustParseAddr("93.184.216.34"),
				netip.MustParseAddr("93.184.216.34"), // duplicate
				netip.MustParseAddr("2606:2800:220:1::1"),
			}, nil
		case "v6only.example.com":
			return []netip.Addr{netip.MustParseAddr("2606:2800:220:1::1")}, nil
		}
		return nil, errors.New("nxdomain")
	}

	tests := []struct {
		in      string
		want    []string
		wantErr string
	}{
		{in: "1.1.1.1", want: []string{"1.1.1.1/32:*"}},
		{in: "1.1.1.1:443", want: []string{"1.1.1.1/32:443"}},
		{in: "10.1.2.3/8", want: []string{"10.0.0.0/8:*"}},
		{in: "10.0.0.0/8:5432", want: []string{"10.0.0.0/8:5432"}},
		{in: "10.0.0.0/8:*", want: []string{"10.0.0.0/8:*"}},
		{in: "api.example.com:443", want: []string{"93.184.216.34/32:443"}},
		{in: "", wantErr: "empty"},
		{in: "1.1.1.1:0", wantErr: "invalid port"},
		{in: "1.1.1.1:70000", wantErr: "invalid port"},
		{in: "::1", wantErr: "IPv6"},
		{in: "v6only.example.com", wantErr: "no IPv4"},
		{in: "missing.example.com", wantErr: "nxdomain"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			rules, err := Parse(tt.in, fakeDNS)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Parse(%q) err = %v, want containing %q", tt.in, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%q): %v", tt.in, err)
			}
			var got []string
			for _, r := range rules {
				got = append(got, r.String())
			}
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Fatalf("Parse(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestKeyMemoryLayout(t *testing.T) {
	r := Rule{Net: netip.MustParsePrefix("10.20.0.0/16"), Port: 443}
	k := r.Key()

	if k.Prefixlen != 48 {
		t.Fatalf("prefixlen = %d, want 48", k.Prefixlen)
	}

	// Lay the fields out the way the kernel sees them and check byte order.
	var port [2]byte
	binary.NativeEndian.PutUint16(port[:], k.Port)
	if port != [2]byte{0x01, 0xBB} {
		t.Fatalf("port bytes = % x, want 01 bb", port)
	}
	var addr [4]byte
	binary.NativeEndian.PutUint32(addr[:], k.Addr)
	if addr != [4]byte{10, 20, 0, 0} {
		t.Fatalf("addr bytes = %v, want 10.20.0.0", addr)
	}
}

func TestRoundTrip(t *testing.T) {
	a := netip.MustParseAddr("192.0.2.7")
	if got := AddrFromKernel(AddrToKernel(a)); got != a {
		t.Fatalf("addr round trip = %v", got)
	}
	if got := Ntohs(Htons(8443)); got != 8443 {
		t.Fatalf("port round trip = %d", got)
	}
}

func TestParseResolvConf(t *testing.T) {
	conf := `# generated
nameserver 127.0.0.53
nameserver 2001:4860:4860::8888
nameserver 8.8.8.8
search corp.example
`
	rules, err := ParseResolvConf(strings.NewReader(conf))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 || rules[0].String() != "127.0.0.53/32:53" || rules[1].String() != "8.8.8.8/32:53" {
		t.Fatalf("rules = %v", rules)
	}
}
