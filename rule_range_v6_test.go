package ipacl

import (
	"testing"
)

func TestRuleRangeV6ListAddRange(t *testing.T) {
	type testCase struct {
		list, r, want string
	}
	runTestCases := func(t *testing.T, testCases []testCase) {
		for _, tc := range testCases {
			list := mustParseRuleRangeV6List(tc.list)
			r := mustParseRuleRangeV6(tc.r)
			added := ruleRangeV6ListAddRange(list, r)
			got := formatRuleRangeV6List(added)
			if got != tc.want {
				t.Errorf("result mismatch, list=%s, r=%s,\n got=%s,\nwant=%s", tc.list, tc.r, got, tc.want)
			}
		}
	}

	t.Run("sameAction", func(t *testing.T) {
		runTestCases(t, []testCase{
			{list: "", r: "2001:db8::4-2001:db8::7", want: "2001:db8::4-2001:db8::7"},
			{list: "2001:db8::4-2001:db8::7", r: "2001:db8::8-2001:db8::9", want: "2001:db8::4-2001:db8::9"},
			{list: "::ffff:ffff:ffff:ffff", r: "0:0:0:1::", want: "::ffff:ffff:ffff:ffff-0:0:0:1::"},
		})
	})
	t.Run("differentAction", func(t *testing.T) {
		runTestCases(t, []testCase{
			{list: "", r: "!2001:db8::4-2001:db8::7", want: "!2001:db8::4-2001:db8::7"},
			{list: "!2001:db8::4-2001:db8::7", r: "2001:db8::8-2001:db8::9",
				want: "!2001:db8::4-2001:db8::7, 2001:db8::8-2001:db8::9"},
			{list: "::ffff:ffff:ffff:ffff", r: "!0:0:0:1::", want: "::ffff:ffff:ffff:ffff, !0:0:0:1::"},
		})
	})
}
