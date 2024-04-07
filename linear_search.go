package ipacl

import (
	"net/netip"
)

type linearSearch struct {
	rules []Rule
}

func newLinearSearch(rules []Rule) linearSearch {
	return linearSearch{
		rules: rules,
	}
}

func (s *linearSearch) Lookup(ip netip.Addr) Action {
	for i := range s.rules {
		if s.rules[i].target.Contains(ip) {
			return s.rules[i].action
		}
	}
	panic("unreachable")
}
