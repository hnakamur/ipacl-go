package ipacl

import (
	"strings"
	"unicode"
)

type binarySearchBuilderV4 struct {
	rules []ruleRangeV4
}

type ruleRangeV4 struct {
	ipRange v4Range
	action  Action
}

func ruleRangeV4FromCIDR(rule Rule) ruleRangeV4 {
	return ruleRangeV4{
		ipRange: v4RangeFromPrefix(rule.target),
		action:  rule.action,
	}
}

// ruleRangeV4ListSubtractList subtracts iist2 from list1 and returns the result.
// Elements in list1 and list2 must be non-overlapping and be sorted in increasing order.
func ruleRangeV4ListSubtractList(list1, list2 []ruleRangeV4) []ruleRangeV4 {
	res := list1
	for _, elem := range list2 {
		res = ruleRangeV4ListSubtractRange(res, elem)
	}
	return res
}

// ruleRangeV4ListSubtractRange subtracts list from s and returns the result.
// Elements in list must be non-overlapping and be sorted in increasing order.
func ruleRangeV4ListSubtractRange(list []ruleRangeV4, s ruleRangeV4) []ruleRangeV4 {
	res := make([]ruleRangeV4, 0, len(list))
	for _, elem := range list {
		res = append(res, ruleRangeV4SubtractRange(elem, s)...)
	}
	return res
}

// ruleRangeV4SubtractRange subtracts s from r and returns the result.
func ruleRangeV4SubtractRange(r, s ruleRangeV4) []ruleRangeV4 {
	var res []ruleRangeV4
	if r.ipRange.Overlaps(s.ipRange) {
		if r.ipRange.start.Compare(s.ipRange.start) < 0 {
			res = append(res, ruleRangeV4{
				ipRange: v4Range{
					start: r.ipRange.start,
					end:   s.ipRange.start.Prev(),
				},
				action: r.action,
			})
		}
		if r.ipRange.end.Compare(s.ipRange.end) > 0 {
			res = append(res, ruleRangeV4{
				ipRange: v4Range{
					start: s.ipRange.end.Next(),
					end:   r.ipRange.end,
				},
				action: r.action,
			})
		}
	} else {
		res = append(res, r)
	}
	return res
}

// ruleRangeV4ListMerge merges list1 and list2.
// Adjacent elements of the same action are concatenated.
// Elements in list1 and list2 must be non-overlapping and be sorted in increasing order.
func ruleRangeV4ListMerge(list1, list2 []ruleRangeV4) []ruleRangeV4 {
	var res []ruleRangeV4
	i := 0
	j := 0
	k := 0

	processList1Item := func() {
		r := list1[i]
		if k > 0 && res[k-1].action == r.action && res[k-1].ipRange.end.Next().Compare(r.ipRange.start) == 0 {
			res[k-1].ipRange.end = r.ipRange.end
		} else {
			res = append(res, r)
			i++
			k++
		}
	}

	processList2Item := func() {
		s := list2[j]
		if k > 0 && res[k-1].action == s.action && res[k-1].ipRange.end.Next().Compare(s.ipRange.start) == 0 {
			res[k-1].ipRange.end = s.ipRange.end
		} else {
			res = append(res, s)
			j++
			k++
		}
	}

	for i < len(list1) && j < len(list2) {
		r := list1[i]
		s := list2[j]
		if r.ipRange.start.Compare(s.ipRange.start) < 0 {
			processList1Item()
		} else {
			processList2Item()
		}
	}
	for i < len(list1) {
		processList1Item()
	}
	for j < len(list2) {
		processList2Item()
	}
	return res
}

func (r ruleRangeV4) String() string {
	var b strings.Builder
	if r.action == Deny {
		b.WriteByte('!')
	}
	b.WriteString(r.ipRange.start.String())
	if r.ipRange.end.Compare(r.ipRange.start) != 0 {
		b.WriteByte('-')
		b.WriteString(r.ipRange.end.String())
	}
	return b.String()
}

func parseRuleRangeV4(s string) (ruleRangeV4, error) {
	action := Allow
	if strings.HasPrefix(s, "!") {
		action = Deny
		s = s[1:]
	}
	before, after, found := strings.Cut(s, "-")
	start, err := parseV4Addr(before)
	if err != nil {
		return ruleRangeV4{}, err
	}
	var end v4Addr
	if found {
		end, err = parseV4Addr(after)
		if err != nil {
			return ruleRangeV4{}, err
		}
	} else {
		end = start
	}
	return ruleRangeV4{
		ipRange: v4Range{start: start, end: end},
		action:  action,
	}, nil
}

func mustParseRuleRangeV4(s string) ruleRangeV4 {
	rule, err := parseRuleRangeV4(s)
	if err != nil {
		panic(err.Error())
	}
	return rule
}

func parseRuleRangeV4List(s string) ([]ruleRangeV4, error) {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return unicode.IsSpace(r) || r == ','
	})
	rules := make([]ruleRangeV4, 0, len(fields))
	for _, field := range fields {
		rule, err := parseRuleRangeV4(field)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func mustParseRuleRangeV4List(s string) []ruleRangeV4 {
	rules, err := parseRuleRangeV4List(s)
	if err != nil {
		panic(err.Error())
	}
	return rules
}

func formatRuleRangeV4List(rules []ruleRangeV4) string {
	var b strings.Builder
	for i, rule := range rules {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(rule.String())
	}
	return b.String()
}
