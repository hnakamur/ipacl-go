package ipacl

import (
	"net/netip"
	"testing"
)

func TestV6RangeFromPrefix(t *testing.T) {
	testCases := []struct {
		input, start, end string
	}{
		{input: "2001:db8::/0", start: "::", end: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
		{input: "2001:db8::/32", start: "2001:db8::", end: "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"},
		{input: "2001:db8::/48", start: "2001:db8::", end: "2001:db8:0:ffff:ffff:ffff:ffff:ffff"},
		{input: "2001:db8::/56", start: "2001:db8::", end: "2001:db8:0:ff:ffff:ffff:ffff:ffff"},
		{input: "2001:db8::/64", start: "2001:db8::", end: "2001:db8::ffff:ffff:ffff:ffff"},
		{input: "2001:db8::/128", start: "2001:db8::", end: "2001:db8::"},
	}
	for _, tc := range testCases {
		r := v6RangeFromPrefix(netip.MustParsePrefix(tc.input))
		if got, want := r.start.String(), tc.start; got != want {
			t.Errorf("start address mismatch, input=%s, got=%s, want=%s", tc.input, got, want)
		}
		if got, want := r.end.String(), tc.end; got != want {
			t.Errorf("end address mismatch, input=%s, got=%s, want=%s", tc.input, got, want)
		}
	}
}

func TestV6Addr_Next(t *testing.T) {
	t.Run("wrap", func(t *testing.T) {
		ip := v6AddrFromBytes(netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").As16()).Next()
		if got, want := ip.IsFirst(), true; got != want {
			t.Errorf("result mismatch, got=%v, want=%v", got, want)
		}
	})
	t.Run("carry", func(t *testing.T) {
		got := v6AddrFromBytes(netip.MustParseAddr("::ffff:ffff:ffff:ffff").As16()).Next()
		want := v6AddrFromBytes(netip.MustParseAddr("0:0:0:1::").As16())
		if got.Compare(want) != 0 {
			t.Errorf("result mismatch, got=%s, want=%s", got, want)
		}
	})
}

func TestV6Addr_Max(t *testing.T) {
	a := mustParseV6Addr("2001:db8::")
	b := mustParseV6Addr("2001:db8::1")
	if got, want := a.Max(b), b; got.Compare(want) != 0 {
		t.Errorf("result mismatch, got=%s, want=%s", got, want)
	}
}
