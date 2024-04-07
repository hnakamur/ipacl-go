package ipacl

import (
	"net/netip"
	"strings"
)

const debug = false

// BinarySearch is a type for looking up an IP address in the access control list
// using binary search algorithm.
type BinarySearch struct {
	v4EndAddrs        []v4Addr
	v4EvenIndexIsDeny bool

	v6EndAddrs        []v6Addr
	v6EvenIndexIsDeny bool
}

// NewBinarySearch creates an BinarySearch instance.
func NewBinarySearch(rules []Rule) BinarySearch {
	b := newBinarySearchBuilder(rules)
	return b.toBinarySearch()
}

// Lookup lookups an IP address and returns the action defined in the access control list.
func (s *BinarySearch) Lookup(ip netip.Addr) Action {
	if ip.Is4() {
		target := v4AddrFromBytes(ip.As4())
		if len(s.v4EndAddrs) > 0 {
			i, _ := binarySearchNoDupFunc(s.v4EndAddrs, target, func(e, t v4Addr) int {
				return e.Compare(t)
			})
			if s.isDenyIndexV4(i) {
				return Deny
			}
		}
		return Allow
	}

	target := v6AddrFromBytes(ip.As16())
	if len(s.v6EndAddrs) > 0 {
		i, _ := binarySearchNoDupFunc(s.v6EndAddrs, target, func(e, t v6Addr) int {
			return e.Compare(t)
		})
		if s.isDenyIndexV6(i) {
			return Deny
		}
	}
	return Allow
}

// binarySearchNoDupFunc searches for target in a sorted slice and returns
// the position where target is found, or the position where target would
// appear in the sort order; it also returns a bool saying whether the target
// is really found in the slice.
//
// The slice must be sorted in increasing order, where "increasing" is
// defined by cmp. cmp should return 0 if the slice element matches the target,
// a negative number if the slice element precedes the target, or a positive
// number if the slice element follows the target. cmp must implement the same
// ordering as the slice, such that if cmp(a, t) < 0 and cmp(b, t) >= 0, then
// a must precede b in the slice.
//
// Also the slice must not have same values more than once.
// In other words, the slice must not have duplicated values.
func binarySearchNoDupFunc[S ~[]E, E, T any](x S, target T, cmp func(E, T) int) (int, bool) {
	n := len(x)
	i, j := 0, n
	for i < j {
		h := int(uint(i+j) >> 1) // avoid overflow when computing h
		c := cmp(x[h], target)
		if c == 0 {
			// Since we know all values in x are different, we can return now.
			return h, true
		}
		if c < 0 {
			i = h + 1
		} else {
			j = h
		}
	}
	return i, false
}

func (s *BinarySearch) isDenyIndexV4(i int) bool {
	if s.v4EvenIndexIsDeny {
		return i%2 == 0
	}
	return i%2 == 1
}

func (s *BinarySearch) isDenyIndexV6(i int) bool {
	if s.v6EvenIndexIsDeny {
		return i%2 == 0
	}
	return i%2 == 1
}

func (s *BinarySearch) String() string {
	var b strings.Builder
	b.WriteString("BinarySearch{v4:[")
	for i := range s.v4EndAddrs {
		if i > 0 {
			b.WriteString(", ")
		}
		if s.isDenyIndexV4(i) {
			b.WriteByte('!')
		}
		var startAddr v4Addr
		if i > 0 {
			startAddr = s.v4EndAddrs[i-1].Next()
		}
		b.WriteString(startAddr.String())
		if s.v4EndAddrs[i].Compare(startAddr) != 0 {
			b.WriteByte('-')
			b.WriteString(s.v4EndAddrs[i].String())
		}
	}
	b.WriteString("], v6:[")
	for i := range s.v6EndAddrs {
		if i > 0 {
			b.WriteString(", ")
		}
		if s.isDenyIndexV6(i) {
			b.WriteByte('!')
		}
		var startAddr v6Addr
		if i > 0 {
			startAddr = s.v6EndAddrs[i-1].Next()
		}
		b.WriteString(startAddr.String())
		if s.v6EndAddrs[i].Compare(startAddr) != 0 {
			b.WriteByte('-')
			b.WriteString(s.v6EndAddrs[i].String())
		}
	}
	b.WriteString("]}")
	return b.String()
}

type binarySearchBuilder struct {
	v4Rules []ruleRangeV4
	v6Rules []ruleRangeV6
}

func newBinarySearchBuilder(rules []Rule) *binarySearchBuilder {
	var b binarySearchBuilder
	for _, rule := range rules {
		b.insertRule(rule)
	}
	return &b
}

func (b *binarySearchBuilder) toBinarySearch() BinarySearch {
	var s BinarySearch

	s.v4EndAddrs = make([]v4Addr, len(b.v4Rules))
	for i, r := range b.v4Rules {
		if i == 0 {
			s.v4EvenIndexIsDeny = r.action == Deny
		}
		s.v4EndAddrs[i] = r.ipRange.end
	}

	s.v6EndAddrs = make([]v6Addr, len(b.v6Rules))
	for i, r := range b.v6Rules {
		if i == 0 {
			s.v6EvenIndexIsDeny = r.action == Deny
		}
		s.v6EndAddrs[i] = r.ipRange.end
	}

	return s
}

func (b *binarySearchBuilder) insertRule(rule Rule) {
	if rule.target.Addr().Is4() {
		v4Rule := ruleRangeV4FromCIDR(rule)
		b.v4Rules = ruleRangeV4ListAddRange(b.v4Rules, v4Rule)
	} else {
		v6Rule := ruleRangeV6FromCIDR(rule)
		b.v6Rules = ruleRangeV6ListAddRange(b.v6Rules, v6Rule)
	}
}
