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
			want:  "BinarySearch{v4:[192.0.2.0-192.0.2.23], v6:[], action:deny}",
		},
		// {
		// 	rules: "deny 192.0.2.0/28\ndeny 192.0.2.16/29\nallow 192.0.2.16/28\ndeny 192.0.2.24/29",
		// 	want:  "BinarySearch{v4:[192.0.2.0-192.0.2.23], v6:[], action:deny}",
		// },
		// {
		// 	rules: "deny 192.0.0.0/0\nallow 192.168.1.0/01\ndeny all",
		// 	want:  "BinarySearch{v4Rules: [], v6Rules: [], action: allow}",
		// },
		// {
		// 	rules: "deny 0.0.0.7\ndeny 0.0.0.1\ndeny 0.0.0.0",
		// 	want:  "BinarySearch{v4Rules: [{start: 0.0.0.0, end: 0.0.0.1}, {start: 0.0.0.7, end: 0.0.0.7}], v6Rules: [], action: deny}",
		// },
		// {
		// 	rules: "deny ::7\ndeny ::1\ndeny ::",
		// 	want:  "BinarySearch{v4Rules: [], v6Rules: [{start: ::, end: ::1}, {start: ::7, end: ::7}], action: deny}",
		// },
		// {
		// 	rules: "allow 0.0.0.7\ndeny 0.0.0.1\ndeny 0.0.0.0",
		// 	want:  "BinarySearch{v4Rules: [{start: 0.0.0.0, end: 0.0.0.1}], v6Rules: [], action: deny}",
		// },
		// {
		// 	rules: "allow ::7\ndeny ::1\ndeny ::",
		// 	want:  "BinarySearch{v4Rules: [], v6Rules: [{start: ::, end: ::1}], action: deny}",
		// },
		// {
		// 	rules: "allow 0.0.0.2\ndeny 0.0.0.1\ndeny 0.0.0.0",
		// 	want:  "BinarySearch{v4Rules: [{start: 0.0.0.0, end: 0.0.0.1}], v6Rules: [], action: deny}",
		// },
		// {
		// 	rules: "allow ::2\ndeny ::1\ndeny ::",
		// 	want:  "BinarySearch{v4Rules: [], v6Rules: [{start: ::, end: ::1}], action: deny}",
		// },
		// {
		// 	rules: "deny 192.0.0.1\nallow 0.0.0.1\nallow 192.0.0.0/7\nallow 0.0.0.0",
		// 	want:  "BinarySearch{v4Rules: [{start: 192.0.0.1, end: 192.0.0.1}], v6Rules: [], action: deny}",
		// },
		// {
		// 	rules: `
		// 	deny  192.168.1.1
		// 	allow 192.0.0.0/0
		// 	deny  all
		// `,
		// 	want: "BinarySearch{v4Rules: [{start: 0.0.0.0, end: 192.168.1.0}, {start: 192.168.1.2, end: 255.255.255.255}], v6Rules: [], action: allow}",
		// },
		// {
		// 	rules: `
		// 		deny 192.0.2.2
		// 		deny 192.0.2.1
		// 	`,
		// 	want: "BinarySearch{v4Rules: [{start: 192.0.2.1, end: 192.0.2.2}], v6Rules: [], action: deny}",
		// },
		// {
		// 	rules: `
		// 		deny 192.0.2.1
		// 		deny 192.0.2.2
		// 	`,
		// 	want: "BinarySearch{v4Rules: [{start: 192.0.2.1, end: 192.0.2.2}], v6Rules: [], action: deny}",
		// },
		// {
		// 	rules: `
		// 		deny 192.0.2.1
		// 		deny 192.0.2.2
		// 	`,
		// 	want: "BinarySearch{v4Rules: [{start: 192.0.2.1, end: 192.0.2.2}], v6Rules: [], action: deny}",
		// },
		// {
		// 	rules: `
		// 		deny 192.0.2.1
		// 		deny 192.0.2.2
		// 		deny 192.0.2.2/31
		// 	`,
		// 	want: "BinarySearch{v4Rules: [{start: 192.0.2.1, end: 192.0.2.3}], v6Rules: [], action: deny}",
		// },
		// {
		// 	rules: `
		// 		deny 192.0.2.0/30
		// 		deny 192.0.2.2/31
		// 	`,
		// 	want: "BinarySearch{v4Rules: [{start: 192.0.2.0, end: 192.0.2.3}], v6Rules: [], action: deny}",
		// },
		// {
		// 	rules: `
		// 		deny 192.0.2.0/29
		// 		deny 192.0.2.2/31
		// 	`,
		// 	want: "BinarySearch{v4Rules: [{start: 192.0.2.0, end: 192.0.2.7}], v6Rules: [], action: deny}",
		// },
		// {
		// 	rules: `
		// 		deny 192.0.2.1
		// 		deny 192.0.2.3
		// 		deny 192.0.2.5
		// 		deny 192.0.2.0/29
		// 	`,
		// 	want: "BinarySearch{v4Rules: [{start: 192.0.2.0, end: 192.0.2.7}], v6Rules: [], action: deny}",
		// },
		// {
		// 	rules: `
		// 		deny 192.0.2.1
		// 		deny 192.0.2.3
		// 		deny 192.0.2.5
		// 		allow 192.0.2.7
		// 		deny 192.0.2.0/29
		// 	`,
		// 	want: "BinarySearch{v4Rules: [{start: 192.0.2.0, end: 192.0.2.6}], v6Rules: [], action: deny}",
		// },
		// {
		// 	rules: `
		// 		deny 192.0.2.1
		// 		deny 192.0.2.3
		// 		deny 192.0.2.5
		// 		allow 192.0.2.7
		// 		deny 192.0.2.0/28
		// 	`,
		// 	want: "BinarySearch{v4Rules: [{start: 192.0.2.0, end: 192.0.2.6}, {start: 192.0.2.8, end: 192.0.2.15}], v6Rules: [], action: deny}",
		// },
		// {
		// 	rules: `
		// 		deny 192.0.2.1
		// 		deny 192.0.2.3
		// 		deny 192.0.2.5
		// 		allow 192.0.2.7
		// 		deny 192.0.2.15
		// 		deny 192.0.2.0/28
		// 	`,
		// 	want: "BinarySearch{v4Rules: [{start: 192.0.2.0, end: 192.0.2.6}, {start: 192.0.2.8, end: 192.0.2.15}], v6Rules: [], action: deny}",
		// },
		// {
		// 	rules: `
		// 		deny 192.0.2.1
		// 		deny 192.0.2.3
		// 		deny 192.0.2.5
		// 		allow 192.0.2.7
		// 		deny 192.0.2.16
		// 		deny 192.0.2.0/28
		// 	`,
		// 	want: "BinarySearch{v4Rules: [{start: 192.0.2.0, end: 192.0.2.6}, {start: 192.0.2.8, end: 192.0.2.16}], v6Rules: [], action: deny}",
		// },
		// {
		// 	rules: `
		// 		deny 192.0.2.1
		// 		deny 192.0.2.3
		// 		deny 192.0.2.5
		// 		allow 192.0.2.7
		// 		allow 192.0.2.13
		// 		allow 192.0.2.14
		// 		deny 192.0.2.16
		// 		deny 192.0.2.0/28
		// 	`,
		// 	want: "BinarySearch{v4Rules: [{start: 192.0.2.0, end: 192.0.2.6}, {start: 192.0.2.8, end: 192.0.2.12}, {start: 192.0.2.15, end: 192.0.2.16}], v6Rules: [], action: deny}",
		// },
		// {
		// 	rules: `
		// 		deny 192.0.2.1
		// 		deny 192.0.2.3
		// 		deny 192.0.2.5
		// 		allow 192.0.2.7
		// 		deny 192.0.2.16/28
		// 		deny 192.0.2.0/28
		// 	`,
		// 	want: "BinarySearch{v4Rules: [{start: 192.0.2.0, end: 192.0.2.6}, {start: 192.0.2.8, end: 192.0.2.31}], v6Rules: [], action: deny}",
		// },
		// {
		// 	rules: `
		// 		deny 192.0.2.8/30
		// 		deny 192.0.2.4/30
		// 	`,
		// 	want: "BinarySearch{v4Rules: [{start: 192.0.2.4, end: 192.0.2.11}], v6Rules: [], action: deny}",
		// },
		// {
		// 	rules: `
		// 		deny 192.0.2.8/30
		// 		deny 192.0.2.6/31
		// 	`,
		// 	want: "BinarySearch{v4Rules: [{start: 192.0.2.6, end: 192.0.2.11}], v6Rules: [], action: deny}",
		// },
	}
	for i, tc := range testCases {
		rules, defAct, err := ParseRuleLines(strings.NewReader(tc.rules))
		if err != nil {
			t.Fatal(err)
		}
		s := NewBinarySearch(rules, defAct)
		if got := s.String(); got != tc.want {
			t.Errorf("result mismatch, i=%d,\n got=%s\nwant=%s", i, got, tc.want)
		}
	}
}
