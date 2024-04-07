package ipacl

import (
	"cmp"
	"encoding/binary"
	"math/bits"
	"net/netip"
	"strings"
)

type v6Addr struct {
	hi uint64
	lo uint64
}

func v6AddrFromBytes(a16 [16]byte) v6Addr {
	return v6Addr{
		hi: binary.BigEndian.Uint64(a16[:8]),
		lo: binary.BigEndian.Uint64(a16[8:]),
	}
}

func mustParseV6Addr(s string) v6Addr {
	return v6AddrFromBytes(netip.MustParseAddr(s).As16())
}

func parseV6Addr(s string) (v6Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return v6Addr{}, err
	}
	return v6AddrFromBytes(a.As16()), nil
}

func (a v6Addr) As16() [16]byte {
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], uint64(a.hi))
	binary.BigEndian.PutUint64(b[8:], uint64(a.lo))
	return b
}

func (a v6Addr) String() string {
	return netip.AddrFrom16(a.As16()).String()
}

func (a v6Addr) Compare(b v6Addr) int {
	c := cmp.Compare(a.hi, b.hi)
	if c != 0 {
		return c
	}
	return cmp.Compare(a.lo, b.lo)
}

func (a v6Addr) Max(b v6Addr) v6Addr {
	if a.Compare(b) >= 0 {
		return a
	}
	return b
}

func (a v6Addr) Min(b v6Addr) v6Addr {
	if a.Compare(b) <= 0 {
		return a
	}
	return b
}

func (a v6Addr) IsFirst() bool {
	return a.hi == 0 && a.lo == 0
}

func (a v6Addr) IsLast() bool {
	return a.hi == 0xffff_ffff_ffff_ffff && a.lo == 0xffff_ffff_ffff_ffff
}

func (a v6Addr) Next() v6Addr {
	lo, carry := bits.Add64(a.lo, 1, 0)
	hi := a.hi + carry
	return v6Addr{hi: hi, lo: lo}
}

func (a v6Addr) Prev() v6Addr {
	lo, borrow := bits.Sub64(a.lo, 1, 0)
	hi := a.hi - borrow
	return v6Addr{hi: hi, lo: lo}
}

type v6Range struct {
	start v6Addr
	end   v6Addr
}

func v6RangeFromPrefix(p netip.Prefix) v6Range {
	start := v6AddrFromBytes(p.Masked().Addr().As16())
	var end v6Addr
	end.hi = start.hi | (0xffff_ffff_ffff_ffff >> p.Bits())
	end.lo = start.lo | (0xffff_ffff_ffff_ffff >> max(p.Bits()-64, 0))
	return v6Range{start: start, end: end}
}

func (r v6Range) Overlaps(o v6Range) bool {
	// !(r.start.Compare(o.end) > 0 || r.end.Compare(o.start) < 0)
	return r.start.Compare(o.end) <= 0 && r.end.Compare(o.start) >= 0
}

func (r v6Range) IsNeighbor(o v6Range) bool {
	return r.end.Next().Compare(o.start) == 0 || r.start.Prev().Compare(o.end) == 0
}

func (r v6Range) Contains(o v6Range) bool {
	return r.start.Compare(o.start) <= 0 && r.end.Compare(o.end) >= 0
}

func (r v6Range) String() string {
	var b strings.Builder
	b.WriteString(r.start.String())
	if r.end.Compare(r.start) != 0 {
		b.WriteByte('-')
		b.WriteString(r.end.String())
	}
	return b.String()
}

type v6RangeRule struct {
	v6Range
	action Action
}

func toV6RangeRule(rule Rule) v6RangeRule {
	return v6RangeRule{
		v6Range: v6RangeFromPrefix(rule.target),
		action:  rule.action,
	}
}

func (r v6RangeRule) String() string {
	var b strings.Builder
	if r.action == Deny {
		b.WriteByte('!')
	}
	b.WriteString(r.v6Range.start.String())
	if r.v6Range.end.Compare(r.v6Range.start) != 0 {
		b.WriteByte('-')
		b.WriteString(r.v6Range.end.String())
	}
	return b.String()
}
