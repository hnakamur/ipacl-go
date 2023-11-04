package ipacl

//go:generate sh -c "./gen_rule_range_v6_go.sh"

import (
	"log"
	"strings"
	"unicode"
)

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

// ruleRangeV4ListAddRange returns a new list with r added to list.
// If an element in list overlaps r, overlapping part is not added.
// Adjacent elements of the same action are concatenated.
// Elements in list must be non-overlapping and be sorted in increasing order.
func ruleRangeV4ListAddRange(list []ruleRangeV4, r ruleRangeV4) []ruleRangeV4 {
	if debug {
		log.Printf("ruleRangeV4ListAddRange start, list=%s, r=%s", list, r)
	}
	var res []ruleRangeV4

	appendOrExtend := func(s ruleRangeV4) {
		j := len(res)
		if j > 0 && res[j-1].action == s.action && res[j-1].ipRange.end.Next().Compare(s.ipRange.start) == 0 {
			res[j-1].ipRange.end = s.ipRange.end
		} else {
			res = append(res, s)
		}
	}

	rest := r
	restEmpty := false
	i := 0
	for i < len(list) {
		s := list[i]
		if debug {
			log.Printf("ruleRangeV4ListAddRange for loop, i=%d, len=%d, s=%s, rest=%s", i, len(list), s, rest)
		}
		if s.ipRange.start.Compare(rest.ipRange.start) <= 0 {
			appendOrExtend(s)
			i++
			sEndNext := s.ipRange.end.Next()
			if sEndNext.Compare(rest.ipRange.start) > 0 || sEndNext.IsFirst() {
				rest.ipRange.start = sEndNext
			}
			if debug {
				log.Printf("ruleRangeV4ListAddRange after add s, i=%d, rest=%s, res=%s", i, rest, formatRuleRangeV4List(res))
			}
		} else {
			end := rest.ipRange.end.Min(s.ipRange.start.Prev())
			appendOrExtend(ruleRangeV4{
				ipRange: v4Range{
					start: rest.ipRange.start,
					end:   end,
				},
				action: rest.action,
			})
			rest.ipRange.start = end.Next()
			if debug {
				log.Printf("ruleRangeV4ListAddRange after add partial or whole rest, i=%d, rest=%s, res=%s", i, rest, formatRuleRangeV4List(res))
			}
		}
		if rest.ipRange.start.Compare(rest.ipRange.end) > 0 || rest.ipRange.start.IsFirst() {
			if debug {
				log.Printf("ruleRangeV4ListAddRange set restEmpty to true, rest=%s", rest)
			}
			restEmpty = true
			break
		}
	}
	if restEmpty {
		for i < len(list) {
			appendOrExtend(list[i])
			i++
			if debug {
				log.Printf("ruleRangeV4ListAddRange added list[i] in loop#2, i=%d, len=%d, res=%s", i, len(list), formatRuleRangeV4List(res))
			}
		}
	} else {
		appendOrExtend(rest)
		if debug {
			log.Printf("ruleRangeV4ListAddRange added rest, res=%s", formatRuleRangeV4List(res))
		}
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
