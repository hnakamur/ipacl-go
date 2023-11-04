package ipacl

import (
	"testing"
)

func TestRuleRangeV4SubtractRange(t *testing.T) {
	testCases := []struct {
		r, s, want string
	}{
		{r: "192.0.2.0-192.0.2.3", s: "192.0.2.4-192.0.2.7", want: "192.0.2.0-192.0.2.3"},
		{r: "192.0.2.0-192.0.2.3", s: "192.0.2.2-192.0.2.3", want: "192.0.2.0-192.0.2.1"},
		{r: "192.0.2.0-192.0.2.3", s: "192.0.2.2-192.0.2.7", want: "192.0.2.0-192.0.2.1"},
		{r: "192.0.2.0-192.0.2.3", s: "192.0.2.0-192.0.2.3", want: ""},
		{r: "192.0.2.4-192.0.2.7", s: "192.0.2.0-192.0.2.3", want: "192.0.2.4-192.0.2.7"},
		{r: "192.0.2.4-192.0.2.7", s: "192.0.2.0-192.0.2.4", want: "192.0.2.5-192.0.2.7"},
		{r: "192.0.2.4-192.0.2.7", s: "192.0.2.0-192.0.2.8", want: ""},
		{r: "192.0.2.4-192.0.2.7", s: "192.0.2.5-192.0.2.6", want: "192.0.2.4, 192.0.2.7"},
		{r: "192.0.2.3-192.0.2.8", s: "192.0.2.5-192.0.2.6", want: "192.0.2.3-192.0.2.4, 192.0.2.7-192.0.2.8"},
	}
	for _, tc := range testCases {
		r := mustParseRuleRangeV4(tc.r)
		s := mustParseRuleRangeV4(tc.s)
		res := ruleRangeV4SubtractRange(r, s)
		got := formatRuleRangeV4List(res)
		if got != tc.want {
			t.Errorf("result mismatch, r=%s, s=%s, got=%s, want=%s", tc.r, tc.s, got, tc.want)
		}
	}
}

func TestRuleRangeV4ListSubtractListt(t *testing.T) {
	testCases := []struct {
		r, s, want string
	}{
		{r: "192.0.2.0-192.0.2.3", s: "192.0.2.4-192.0.2.7", want: "192.0.2.0-192.0.2.3"},
		{r: "192.0.2.0-192.0.2.3", s: "192.0.2.2-192.0.2.3", want: "192.0.2.0-192.0.2.1"},
		{r: "192.0.2.0-192.0.2.3", s: "192.0.2.2-192.0.2.7", want: "192.0.2.0-192.0.2.1"},
		{r: "192.0.2.0-192.0.2.3", s: "192.0.2.0-192.0.2.3", want: ""},
		{r: "192.0.2.4-192.0.2.7", s: "192.0.2.0-192.0.2.3", want: "192.0.2.4-192.0.2.7"},
		{r: "192.0.2.4-192.0.2.7", s: "192.0.2.0-192.0.2.4", want: "192.0.2.5-192.0.2.7"},
		{r: "192.0.2.4-192.0.2.7", s: "192.0.2.0-192.0.2.8", want: ""},
		{r: "192.0.2.4-192.0.2.7", s: "192.0.2.5-192.0.2.6", want: "192.0.2.4, 192.0.2.7"},
		{r: "192.0.2.3-192.0.2.8", s: "192.0.2.5-192.0.2.6", want: "192.0.2.3-192.0.2.4, 192.0.2.7-192.0.2.8"},
	}
	for _, tc := range testCases {
		r := mustParseRuleRangeV4(tc.r)
		s := mustParseRuleRangeV4(tc.s)
		res := ruleRangeV4SubtractRange(r, s)
		got := formatRuleRangeV4List(res)
		if got != tc.want {
			t.Errorf("result mismatch, r=%s, s=%s, got=%s, want=%s", tc.r, tc.s, got, tc.want)
		}
	}
}
