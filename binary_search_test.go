package ipacl

import (
	"net/netip"
	"strings"
	"testing"
)

type testCase struct {
	input string
	want  Action
}

type testRulesAndCases struct {
	rules string
	cases []testCase
}

var testRulesAndCasesData = []testRulesAndCases{
	{
		rules: "allow 0.0.0.2\ndeny 0.0.0.1\ndeny 0.0.0.0",
		cases: []testCase{
			{input: "0.0.0.1", want: Deny},
		},
	},
	{
		rules: "deny 192.0.0.1\nallow 0.0.0.1\nallow 192.0.0.0/7\nallow 0.0.0.0",
		cases: []testCase{
			{input: "::", want: Allow},
		},
	},
	{
		rules: `
			deny  192.168.1.1
			allow 192.0.0.0/0
			deny  all
		`,
		cases: []testCase{
			{input: "192.168.1.1", want: Deny},
		},
	},
	{
		rules: `
		deny  192.168.1.1
		allow 192.168.1.0/24
		allow 10.1.1.0/16
		allow 2001:0db8::/32
		deny  all
	`,
		cases: []testCase{
			{input: "0.0.0.0", want: Deny},
			{input: "192.168.0.255", want: Deny},
			{input: "192.168.1.0", want: Allow},
			{input: "192.168.1.1", want: Deny},
			{input: "192.168.1.2", want: Allow},
			{input: "192.168.1.255", want: Allow},
			{input: "192.168.2.0", want: Deny},
			{input: "10.0.255.255", want: Deny},
			{input: "10.1.0.0", want: Allow},
			{input: "10.1.255.255", want: Allow},
			{input: "10.2.0.0", want: Deny},
			{input: "255.255.255.255", want: Deny},
			{input: "::", want: Deny},
			{input: "2001:0db7:ffff:ffff:ffff:ffff:ffff:ffff", want: Deny},
			{input: "2001:0db8::", want: Allow},
			{input: "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", want: Allow},
			{input: "2001:db9::", want: Deny},
			{input: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", want: Deny},
		},
	},
}

func TestBinarySearch_Lookup(t *testing.T) {
	for i, rulesAndCases := range testRulesAndCasesData {
		rules, defAct, err := ParseRuleLines(strings.NewReader(rulesAndCases.rules))
		if err != nil {
			t.Fatal(err)
		}
		s := NewBinarySearch(rules, defAct)
		for _, tc := range rulesAndCases.cases {
			got := s.Lookup(netip.MustParseAddr(tc.input))
			if got != tc.want {
				t.Errorf("result mismatch, rules=%d, input=%s, got=%s, want=%s", i, tc.input, got, tc.want)
			}
		}
	}
}

func TestBinarySearch_String(t *testing.T) {
	testCases := []struct {
		rules string
		want  string
	}{
		{
			rules: "deny 192.0.2.0/28\ndeny 192.0.2.16/29",
			want:  "BinarySearch{v4:[!192.0.2.0-192.0.2.23], v6:[]}",
		},
		{
			rules: "deny 192.0.2.0/28\ndeny 192.0.2.24/29",
			want:  "BinarySearch{v4:[!192.0.2.0-192.0.2.15, !192.0.2.24-192.0.2.31], v6:[]}",
		},
		{
			rules: `
				deny  192.168.1.1
				allow 192.168.1.0/24
				allow 10.1.1.0/16
				allow 2001:0db8::/32
				deny  all
			`,
			want: "BinarySearch{v4:[10.1.0.0-10.1.255.255, 192.168.1.0, 192.168.1.2-192.168.1.255], " +
				"v6:[2001:db8::-2001:db8:ffff:ffff:ffff:ffff:ffff:ffff]}",
		},
	}
	for i, tc := range testCases {
		rules, defAct, err := ParseRuleLines(strings.NewReader(tc.rules))
		if err != nil {
			t.Fatal(err)
		}
		s := NewBinarySearch(rules, defAct)
		if got := s.String(); got != tc.want {
			t.Errorf("result mismatch, i=%d, rules=%s\n got=%s\nwant=%s", i, tc.rules, got, tc.want)
		}
	}
}

func FuzzBinarySearch_Lookup(f *testing.F) {
	f.Add(`
		deny  192.168.1.1
		allow 192.168.1.0/24
		allow 10.1.1.0/16
		allow 2001:0db8::/32
		deny  all
		`, "192.168.1.1")
	f.Add(`
		deny  192.168.1.1
		allow 192.168.1.0/24
		allow 10.1.1.0/16
		allow 2001:0db8::/32
		deny  all
		`, "2001:0db8::")
	f.Fuzz(func(t *testing.T, s, input string) {
		rules, defAct, err := ParseRuleLines(strings.NewReader(s))
		if err != nil {
			t.Skip()
		}
		target, err := netip.ParseAddr(input)
		if err != nil || strings.Contains(target.String(), "%") {
			t.Skip()
		}
		bs := NewBinarySearch(rules, defAct)
		ls := newLinearSearch(rules, defAct)
		got := bs.Lookup(target)
		want := ls.Lookup(target)
		if got != want {
			t.Errorf("result mismatch, got=%s, want=%s", got, want)
		}
	})
}
