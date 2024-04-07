// Package ipacl provides feature for access control by an requester's IP address.
package ipacl

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Action is the type of the action for a rule.
type Action int

const (
	// Allow allows an IP address in the target CIDR.
	Allow Action = iota + 1
	// Deny denies an IP address in the target CIDR.
	Deny
)

// Rule is a unit of rule to allow or deny IP addresses in the target CIDR.
type Rule struct {
	target netip.Prefix
	action Action
}

// NewRule creates a rule with a CIDR and an action.
func NewRule(target netip.Prefix, action Action) Rule {
	return Rule{target: target, action: action}
}

// String returns the string representation of the rule.
func (r Rule) String() string {
	return fmt.Sprintf("%s %s", r.action, r.target)
}

type Rules []Rule

func (r Rules) String() string {
	var b strings.Builder
	for i, rr := range r {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(rr.String())
	}
	return b.String()
}

// ParseAction parses an action.
func ParseAction(s string) (Action, error) {
	switch s {
	case "allow":
		return Allow, nil
	case "deny":
		return Deny, nil
	default:
		return Action(0), errors.New(`invalid Action, must be "allow" or "deny"`)
	}
}

// Negated returns the negated action.
func (a Action) Negated() Action {
	switch a {
	case Allow:
		return Deny
	case Deny:
		return Allow
	default:
		panic("invalid Action")
	}
}

// String returns the string representation of the action.
func (a Action) String() string {
	switch a {
	case Allow:
		return "allow"
	case Deny:
		return "deny"
	default:
		panic("invalid Action")
	}
}

var allIPv4CIDR = netip.PrefixFrom(netip.AddrFrom4([4]byte{}), 0)
var allIPv6CIDR = netip.PrefixFrom(netip.AddrFrom16([16]byte{}), 0)

// ParseRuleLines parses rules in multiple lines.
func ParseRuleLines(s string) (rules []Rule, err error) {
	seenV4DefaultAction := false
	seenV6DefaultAction := false

	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lineNo := i + 1
		line, _, _ := strings.Cut(line, "#")
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("two fields must exist at line %d", lineNo)
		}
		action, err := ParseAction(fields[0])
		if err != nil {
			return nil, fmt.Errorf(`invalid action %q at line %d, must be "allow" or "deny"`, fields[0], lineNo)
		}

		var target netip.Prefix
		if fields[1] == "all" {
			rules = append(rules, NewRule(allIPv4CIDR, action))
			seenV4DefaultAction = true
			rules = append(rules, NewRule(allIPv6CIDR, action))
			seenV6DefaultAction = true
		} else {
			target, err = netip.ParsePrefix(fields[1])
			if err != nil {
				ip, err := netip.ParseAddr(fields[1])
				if err != nil {
					return nil, fmt.Errorf(`invalid target %q at line %d, must be a valid a IPv4 CIDR, address or "all"`, fields[1], lineNo)
				} else if strings.Contains(target.String(), "%") {
					return nil, fmt.Errorf(`invalid target %q at line %d, must not contain "%%"`, fields[1], lineNo)
				}
				target = netip.PrefixFrom(ip, 32)
			} else if strings.Contains(target.String(), "%") {
				return nil, fmt.Errorf(`invalid target %q at line %d, must not contain "%%"`, fields[1], lineNo)
			}
			rules = append(rules, NewRule(target, action))
			if target.Bits() == 0 {
				if target.Addr().Is4() {
					seenV4DefaultAction = true
				} else {
					seenV6DefaultAction = true
				}
			}
		}
	}

	if !seenV4DefaultAction {
		rules = append(rules, NewRule(allIPv4CIDR, Allow))
	}
	if !seenV6DefaultAction {
		rules = append(rules, NewRule(allIPv6CIDR, Allow))
	}
	return rules, nil
}
