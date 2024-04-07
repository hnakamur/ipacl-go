package ipacl

import (
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestParseRuleLines(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		const maxLines = 100
		testCases := []struct {
			input string
			want  string
		}{
			{input: "# comment\nallow 192.0.2.0/24 # comment\ndeny 198.51.100.0/24\n\n", want: "allow 192.0.2.0/24, deny 198.51.100.0/24, allow 0.0.0.0/0, allow ::/0"},
			{input: "# comment\nallow 192.0.2.0/24 # comment\ndeny 198.51.100.0/24\nallow all\n", want: "allow 192.0.2.0/24, deny 198.51.100.0/24, allow 0.0.0.0/0, allow ::/0"},
			{input: "# comment\nallow 192.0.2.0/24 # comment\ndeny 198.51.100.0/24\ndeny all\n", want: "allow 192.0.2.0/24, deny 198.51.100.0/24, deny 0.0.0.0/0, deny ::/0"},
			{input: "# comment\nallow 192.0.2.0/24 # comment\ndeny 198.51.100.0/24\nallow 203.0.113.0/24\n", want: "allow 192.0.2.0/24, deny 198.51.100.0/24, allow 203.0.113.0/24, allow 0.0.0.0/0, allow ::/0"},
			{input: "# comment\nallow 192.0.2.0/24 # comment\ndeny 198.51.100.0/24\nallow 203.0.113.0/0\n", want: "allow 192.0.2.0/24, deny 198.51.100.0/24, allow 203.0.113.0/0, allow ::/0"},
			{input: "# comment\nallow 192.0.2.0/24 # comment\ndeny 198.51.100.0/24\ndeny 203.0.113.0/0\n", want: "allow 192.0.2.0/24, deny 198.51.100.0/24, deny 203.0.113.0/0, allow ::/0"},
			{input: "# empty\n", want: "allow 0.0.0.0/0, allow ::/0"},
			{input: `deny 192.168.255.250/32
			deny 192.168.255.248/32
			deny 192.168.255.246/32
			deny 192.168.255.244/32
			deny 192.168.255.242/32
			deny 192.168.255.240/32
			deny 192.168.255.238/32
			deny 192.168.255.236/32
			deny 192.168.255.234/32
			deny 192.168.255.232/32
			deny 192.168.255.230/32
			deny 192.168.255.228/32
			deny 192.168.255.226/32
			deny 192.168.255.224/32
			deny 192.168.255.222/32
			deny 192.168.255.220/32
			deny 192.168.255.218/32
			deny 192.168.255.216/32
			deny 192.168.255.214/32
			deny 192.168.255.212/32
			deny 192.168.255.210/32
			deny 192.168.255.208/32
			deny 192.168.255.206/32
			deny 192.168.255.204/32
			deny 192.168.255.202/32
			deny 192.168.255.200/32
			deny 192.168.255.198/32
			deny 192.168.255.196/32
			deny 192.168.255.194/32
			deny 192.168.255.192/32
			deny 192.168.255.190/32
			deny 192.168.255.188/32
			deny 192.168.255.186/32
			deny 192.168.255.184/32
			deny 192.168.255.182/32
			deny 192.168.255.180/32
			deny 192.168.255.178/32
			deny 192.168.255.176/32
			deny 192.168.255.174/32
			deny 192.168.255.172/32
			deny 192.168.255.170/32
			deny 192.168.255.168/32
			deny 192.168.255.166/32
			deny 192.168.255.164/32
			deny 192.168.255.162/32
			deny 192.168.255.160/32
			deny 192.168.255.158/32
			deny 192.168.255.156/32
			deny 192.168.255.154/32
			deny 192.168.255.152/32
			deny 192.168.255.150/32
			deny 192.168.255.148/32
			deny 192.168.255.146/32
			deny 192.168.255.144/32
			deny 192.168.255.142/32
			deny 192.168.255.140/32
			deny 192.168.255.138/32
			deny 192.168.255.136/32
			deny 192.168.255.134/32
			deny 192.168.255.132/32
			deny 192.168.255.130/32
			deny 192.168.255.128/32
			deny 192.168.255.126/32
			deny 192.168.255.124/32
			deny 192.168.255.122/32
			deny 192.168.255.120/32
			deny 192.168.255.118/32
			deny 192.168.255.116/32
			deny 192.168.255.114/32
			deny 192.168.255.112/32
			deny 192.168.255.110/32
			deny 192.168.255.108/32
			deny 192.168.255.106/32
			deny 192.168.255.104/32
			deny 192.168.255.102/32
			deny 192.168.255.100/32
			deny 192.168.255.98/32
			deny 192.168.255.96/32
			deny 192.168.255.94/32
			deny 192.168.255.92/32
			deny 192.168.255.90/32
			deny 192.168.255.88/32
			deny 192.168.255.86/32
			deny 192.168.255.84/32
			deny 192.168.255.82/32
			deny 192.168.255.80/32
			deny 192.168.255.78/32
			deny 192.168.255.76/32
			deny 192.168.255.74/32
			deny 192.168.255.72/32
			deny 192.168.255.70/32
			deny 192.168.255.68/32
			deny 192.168.255.66/32
			deny 192.168.255.64/32
			deny 192.168.255.62/32
			deny 192.168.255.60/32
			deny 192.168.255.58/32
			deny 192.168.255.56/32
			deny 192.168.255.54/32
			deny 192.168.255.52/32
			`, want: "deny 192.168.255.250/32, deny 192.168.255.248/32, deny 192.168.255.246/32, deny 192.168.255.244/32, deny 192.168.255.242/32, deny 192.168.255.240/32, deny 192.168.255.238/32, deny 192.168.255.236/32, deny 192.168.255.234/32, deny 192.168.255.232/32, deny 192.168.255.230/32, deny 192.168.255.228/32, deny 192.168.255.226/32, deny 192.168.255.224/32, deny 192.168.255.222/32, deny 192.168.255.220/32, deny 192.168.255.218/32, deny 192.168.255.216/32, deny 192.168.255.214/32, deny 192.168.255.212/32, deny 192.168.255.210/32, deny 192.168.255.208/32, deny 192.168.255.206/32, deny 192.168.255.204/32, deny 192.168.255.202/32, deny 192.168.255.200/32, deny 192.168.255.198/32, deny 192.168.255.196/32, deny 192.168.255.194/32, deny 192.168.255.192/32, deny 192.168.255.190/32, deny 192.168.255.188/32, deny 192.168.255.186/32, deny 192.168.255.184/32, deny 192.168.255.182/32, deny 192.168.255.180/32, deny 192.168.255.178/32, deny 192.168.255.176/32, deny 192.168.255.174/32, deny 192.168.255.172/32, deny 192.168.255.170/32, deny 192.168.255.168/32, deny 192.168.255.166/32, deny 192.168.255.164/32, deny 192.168.255.162/32, deny 192.168.255.160/32, deny 192.168.255.158/32, deny 192.168.255.156/32, deny 192.168.255.154/32, deny 192.168.255.152/32, deny 192.168.255.150/32, deny 192.168.255.148/32, deny 192.168.255.146/32, deny 192.168.255.144/32, deny 192.168.255.142/32, deny 192.168.255.140/32, deny 192.168.255.138/32, deny 192.168.255.136/32, deny 192.168.255.134/32, deny 192.168.255.132/32, deny 192.168.255.130/32, deny 192.168.255.128/32, deny 192.168.255.126/32, deny 192.168.255.124/32, deny 192.168.255.122/32, deny 192.168.255.120/32, deny 192.168.255.118/32, deny 192.168.255.116/32, deny 192.168.255.114/32, deny 192.168.255.112/32, deny 192.168.255.110/32, deny 192.168.255.108/32, deny 192.168.255.106/32, deny 192.168.255.104/32, deny 192.168.255.102/32, deny 192.168.255.100/32, deny 192.168.255.98/32, deny 192.168.255.96/32, deny 192.168.255.94/32, deny 192.168.255.92/32, deny 192.168.255.90/32, deny 192.168.255.88/32, deny 192.168.255.86/32, deny 192.168.255.84/32, deny 192.168.255.82/32, deny 192.168.255.80/32, deny 192.168.255.78/32, deny 192.168.255.76/32, deny 192.168.255.74/32, deny 192.168.255.72/32, deny 192.168.255.70/32, deny 192.168.255.68/32, deny 192.168.255.66/32, deny 192.168.255.64/32, deny 192.168.255.62/32, deny 192.168.255.60/32, deny 192.168.255.58/32, deny 192.168.255.56/32, deny 192.168.255.54/32, deny 192.168.255.52/32, allow 0.0.0.0/0, allow ::/0"},
		}
		for i, tc := range testCases {
			rules, err := ParseRuleLines(tc.input)
			if err != nil {
				t.Errorf("want no error for test case %d, got: %s", i, err.Error())
			} else if diff := gocmp.Diff(tc.want, Rules(rules).String()); diff != "" {
				t.Errorf("rules mismatch for test case %d, (-want +got):\n%s", i, diff)
			}
		}
	})
	t.Run("error", func(t *testing.T) {
		testCases := []struct {
			input string
			want  string
		}{
			{input: "bad_field_count", want: "two fields must exist at line 1"},
			{input: "bad_action 192.0.2.0/24", want: `invalid action "bad_action" at line 1, must be "allow" or "deny"`},
			{input: "allow 192.0.2.256", want: `invalid target "192.0.2.256" at line 1, must be a valid a IPv4 CIDR, address or "all"`},
		}
		for i, tc := range testCases {
			_, err := ParseRuleLines(tc.input)
			if err == nil {
				t.Errorf("got no error for test case %d, want: %s", i, tc.want)
			} else if got, want := err.Error(), tc.want; got != want {
				t.Errorf("error message mismatch for test case %d, got: %s, want: %s", i, got, want)
			}
		}
	})
}
