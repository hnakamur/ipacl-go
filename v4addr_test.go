package ipacl

import (
	"net/netip"
	"testing"
)

func TestV4RangeFromPrefix(t *testing.T) {
	testCases := []struct {
		input, start, end string
	}{
		{input: "192.0.2.1/0", start: "0.0.0.0", end: "255.255.255.255"},
		{input: "192.0.2.1/24", start: "192.0.2.0", end: "192.0.2.255"},
		{input: "192.0.2.1/27", start: "192.0.2.0", end: "192.0.2.31"},
		{input: "192.0.2.0/32", start: "192.0.2.0", end: "192.0.2.0"},
	}
	for _, tc := range testCases {
		r := v4RangeFromPrefix(netip.MustParsePrefix(tc.input))
		if got, want := r.start.String(), tc.start; got != want {
			t.Errorf("start address mismatch, input=%s, got=%s, want=%s", tc.input, got, want)
		}
		if got, want := r.end.String(), tc.end; got != want {
			t.Errorf("end address mismatch, input=%s, got=%s, want=%s", tc.input, got, want)
		}
	}
}

func TestV4Addr_Next(t *testing.T) {
	t.Run("wrap", func(t *testing.T) {
		ip := v4AddrFromBytes(netip.MustParseAddr("255.255.255.255").As4()).Next()
		if got, want := ip.IsFirst(), true; got != want {
			t.Errorf("result mismatch, got=%v, want=%v", got, want)
		}
	})
}

func TestV4Addr_Max(t *testing.T) {
	a := mustParseV4Addr("192.0.2.1")
	b := mustParseV4Addr("192.0.2.2")
	if got, want := a.Max(b), b; got.Compare(want) != 0 {
		t.Errorf("result mismatch, got=%s, want=%s", got, want)
	}
}

func TestV4Range_IsNeighbor(t *testing.T) {
	r1 := v4Range{start: mustParseV4Addr("0.0.0.0"), end: mustParseV4Addr("0.0.0.0")}
	r2 := v4Range{start: mustParseV4Addr("0.0.0.1"), end: mustParseV4Addr("0.0.0.1")}
	if got, want := r1.IsNeighbor(r2), true; got != want {
		t.Errorf("result mismatch, got=%v, want=%v", got, want)
	}
}
