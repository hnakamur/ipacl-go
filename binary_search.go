package ipacl

import (
	"net/netip"
	"strings"
)

const debug = false

type BinarySearch struct {
	v4StartAddrs []v4Addr
	v4EndAddrs   []v4Addr

	v6StartAddrs []v6Addr
	v6EndAddrs   []v6Addr

	action Action
}

func NewBinarySearch(rules []Rule, defaultAction Action) BinarySearch {
	b := newBinarySearchBuilder(rules, defaultAction)
	return b.toBinarySearch()
}

func (s *BinarySearch) Lookup(ip netip.Addr) Action {
	if ip.Is4() {
		target := v4AddrFromBytes(ip.As4())
		if len(s.v4EndAddrs) > 0 {
			i, _ := target.BinarySearch(s.v4EndAddrs)
			if i < len(s.v4StartAddrs) && target >= s.v4StartAddrs[i] {
				return s.action
			}
		}
		return s.action.Negated()
	}

	target := v6AddrFromBytes(ip.As16())
	if len(s.v6EndAddrs) > 0 {
		i, _ := target.BinarySearch(s.v6EndAddrs)
		if i < len(s.v6StartAddrs) && target.Compare(s.v6StartAddrs[i]) >= 0 {
			return s.action
		}
	}
	return s.action.Negated()
}

func (s *BinarySearch) String() string {
	var b strings.Builder
	b.WriteString("BinarySearch{v4:[")
	for i := range s.v4StartAddrs {
		if i > 0 {
			b.WriteString(", ")
		}
		if s.action == Deny {
			b.WriteByte('!')
		}
		b.WriteString(s.v4StartAddrs[i].String())
		if s.v4EndAddrs[i].Compare(s.v4StartAddrs[i]) != 0 {
			b.WriteByte('-')
			b.WriteString(s.v4EndAddrs[i].String())
		}
	}
	b.WriteString("], v6:[")
	for i := range s.v6StartAddrs {
		if i > 0 {
			b.WriteString(", ")
		}
		if s.action == Deny {
			b.WriteByte('!')
		}
		b.WriteString(s.v6StartAddrs[i].String())
		if s.v6EndAddrs[i].Compare(s.v6StartAddrs[i]) != 0 {
			b.WriteByte('-')
			b.WriteString(s.v6EndAddrs[i].String())
		}
	}
	b.WriteString("]}")
	return b.String()
}

type binarySearchBuilder struct {
	v4Rules       []ruleRangeV4
	v6Rules       []ruleRangeV6
	defaultAction Action
}

func newBinarySearchBuilder(rules []Rule, defaultAction Action) *binarySearchBuilder {
	b := binarySearchBuilder{
		defaultAction: defaultAction,
	}
	for _, rule := range rules {
		b.insertRule(rule)
	}
	return &b
}

func (b *binarySearchBuilder) toBinarySearch() BinarySearch {
	s := BinarySearch{
		action: b.defaultAction.Negated(),
	}

	n := 0
	for _, r := range b.v4Rules {
		if r.action != b.defaultAction {
			n++
		}
	}
	s.v4StartAddrs = make([]v4Addr, n)
	s.v4EndAddrs = make([]v4Addr, n)
	j := 0
	for i, a := range b.v4Rules {
		if a.action != b.defaultAction {
			s.v4StartAddrs[j] = b.v4Rules[i].ipRange.start
			s.v4EndAddrs[j] = b.v4Rules[i].ipRange.end
			j++
		}
	}

	n = 0
	for _, r := range b.v6Rules {
		if r.action != b.defaultAction {
			n++
		}
	}
	s.v6StartAddrs = make([]v6Addr, n)
	s.v6EndAddrs = make([]v6Addr, n)
	j = 0
	for i, a := range b.v6Rules {
		if a.action != b.defaultAction {
			s.v6StartAddrs[j] = b.v6Rules[i].ipRange.start
			s.v6EndAddrs[j] = b.v6Rules[i].ipRange.end
			j++
		}
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
