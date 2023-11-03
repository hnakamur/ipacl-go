package ipacl

import (
	"net/netip"
)

type linearSearch struct {
	rules         []Rule
	defaultAction Action
}

func newLinearSearch(rules []Rule, defaultAction Action) linearSearch {
	return linearSearch{
		rules:         rules,
		defaultAction: defaultAction,
	}
}

func (s *linearSearch) Lookup(ip netip.Addr) Action {
	for i := range s.rules {
		if s.rules[i].Target.Contains(ip) {
			return s.rules[i].Action
		}
	}
	return s.defaultAction
}
