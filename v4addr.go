package ipacl

import (
	"cmp"
	"encoding/binary"
	"net/netip"
	"slices"
	"strings"
)

type v4Addr uint32

func v4AddrFromBytes(a4 [4]byte) v4Addr {
	return v4Addr(binary.BigEndian.Uint32(a4[:]))
}

func mustParseV4Addr(s string) v4Addr {
	return v4AddrFromBytes(netip.MustParseAddr(s).As4())
}

func parseV4Addr(s string) (v4Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return v4Addr(0), err
	}
	return v4AddrFromBytes(a.As4()), nil
}

func (a v4Addr) As4() [4]byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(a))
	return b
}

func (a v4Addr) String() string {
	return netip.AddrFrom4(a.As4()).String()
}

func (a v4Addr) Compare(b v4Addr) int {
	return cmp.Compare(a, b)
}

func (a v4Addr) Max(b v4Addr) v4Addr {
	return max(a, b)
}

func (a v4Addr) Min(b v4Addr) v4Addr {
	return min(a, b)
}

func (a v4Addr) BinarySearch(addrs []v4Addr) (int, bool) {
	return slices.BinarySearch(addrs, a)
}

func (a v4Addr) IsFirst() bool {
	return uint32(a) == 0
}

func (a v4Addr) IsLast() bool {
	return uint32(a) == 0xffff_ffff
}

func (a v4Addr) Prev() v4Addr {
	return v4Addr(uint32(a) - 1)
}

func (a v4Addr) Next() v4Addr {
	return v4Addr(uint32(a) + 1)
}

type v4Range struct {
	start v4Addr
	end   v4Addr
}

func v4RangeFromPrefix(p netip.Prefix) v4Range {
	start := v4AddrFromBytes(p.Masked().Addr().As4())
	end := start | (0xffff_ffff >> p.Bits())
	return v4Range{start: start, end: end}
}

func (r v4Range) Overlaps(o v4Range) bool {
	// !(r.start.Compare(o.end) > 0 || r.end.Compare(o.start) < 0)
	return r.start.Compare(o.end) <= 0 && r.end.Compare(o.start) >= 0
}

func (r v4Range) IsNeighbor(o v4Range) bool {
	return r.end.Next().Compare(o.start) == 0 || r.start.Prev().Compare(o.end) == 0
}

func (r v4Range) Contains(o v4Range) bool {
	return r.start.Compare(o.start) <= 0 && r.end.Compare(o.end) >= 0
}

func (r v4Range) String() string {
	var b strings.Builder
	b.WriteString(r.start.String())
	if r.end.Compare(r.start) != 0 {
		b.WriteByte('-')
		b.WriteString(r.end.String())
	}
	return b.String()
}

type v4RangeRule struct {
	v4Range
	action Action
}

func toV4RangeRule(rule Rule) v4RangeRule {
	return v4RangeRule{
		v4Range: v4RangeFromPrefix(rule.target),
		action:  rule.action,
	}
}

func (r v4RangeRule) String() string {
	var b strings.Builder
	if r.action == Deny {
		b.WriteByte('!')
	}
	b.WriteString(r.v4Range.start.String())
	if r.v4Range.end.Compare(r.v4Range.start) != 0 {
		b.WriteByte('-')
		b.WriteString(r.v4Range.end.String())
	}
	return b.String()
}
