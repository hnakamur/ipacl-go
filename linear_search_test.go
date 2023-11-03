package ipacl

import (
	"net/netip"
	"strings"
	"testing"
)

func TestLinearSearch(t *testing.T) {
	for i, rulesAndCases := range testRulesAndCasesData {
		rules, defAct, err := ParseRuleLines(strings.NewReader(rulesAndCases.rules))
		if err != nil {
			t.Fatal(err)
		}
		s := newLinearSearch(rules, defAct)
		for _, tc := range rulesAndCases.cases {
			got := s.Lookup(netip.MustParseAddr(tc.input))
			if got != tc.want {
				t.Errorf("result mismatch, rules=%d, input=%s, got=%s, want=%s", i, tc.input, got, tc.want)
			}
		}
	}
}
