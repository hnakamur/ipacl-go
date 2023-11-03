package ipacl

import (
	"net/netip"
	"testing"
)

func TestNetip(t *testing.T) {
	t.Run("Prefix", func(t *testing.T) {
		t.Run("Addr", func(t *testing.T) {
			p := netip.MustParsePrefix("192.0.2.1/24")
			if got, want := p.Masked().Addr().String(), "192.0.2.0"; got != want {
				t.Errorf("masked address mismatch, got=%s, want=%s", got, want)
			}
			if got, want := p.Bits(), 24; got != want {
				t.Errorf("prefix length mismatch, got=%d, want=%d", got, want)
			}
		})
	})
	t.Run("Next", func(t *testing.T) {
		got := netip.MustParseAddr("::ffff:ffff:ffff:ffff").Next()
		want := netip.MustParseAddr("0:0:0:1::")
		if got.Compare(want) != 0 {
			t.Errorf("result mismatch, got=%s, want=%s", got, want)
		}
	})
}
