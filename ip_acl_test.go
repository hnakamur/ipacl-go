package ipacl

import (
	"net/netip"
	"strings"
	"testing"
)

func FuzzBinarySearch(f *testing.F) {
	f.Add(`
		deny  192.168.1.1
		allow 192.168.1.0/24
		allow 10.1.1.0/16
		allow 2001:0db8::/32
		deny  all
		`, "192.168.1.1")
	f.Add(`
		deny  192.168.1.1
		allow 192.168.1.0/24
		allow 10.1.1.0/16
		allow 2001:0db8::/32
		deny  all
		`, "2001:0db8::")
	f.Fuzz(func(t *testing.T, s, input string) {
		rules, defAct, err := ParseRuleLines(strings.NewReader(s))
		if err != nil {
			t.Skip()
		}
		target, err := netip.ParseAddr(input)
		if err != nil || strings.Contains(target.String(), "%") {
			t.Skip()
		}
		bs := NewBinarySearch(rules, defAct)
		ls := newLinearSearch(rules, defAct)
		got := bs.Lookup(target)
		want := ls.Lookup(target)
		if got != want {
			t.Errorf("result mismatch, got=%s, want=%s", got, want)
		}
	})
}
