// Package ipacl provides feature for access control by an requester's IP address.
package ipacl

import (
	"bufio"
	"errors"
	"fmt"
	"io"
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

// ParseRuleLines parses rules in multiple lines.
func ParseRuleLines(r io.Reader) (rules []Rule, defaultAction Action, err error) {
	scanner := bufio.NewScanner(r)
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, defaultAction, fmt.Errorf("two fields must exist at line %d", lineNo)
		}
		action, err := ParseAction(fields[0])
		if err != nil {
			return nil, defaultAction, fmt.Errorf(`invalid action %q at line %d, must be "allow" or "deny"`, fields[0], lineNo)
		}
		if fields[1] == "all" {
			if defaultAction != Action(0) {
				return nil, defaultAction, fmt.Errorf(`dupliecated line for target "all" at line %d`, lineNo)
			}
			defaultAction = action
		} else {
			target, err := netip.ParsePrefix(fields[1])
			if err != nil {
				ip, err := netip.ParseAddr(fields[1])
				if err != nil {
					return nil, defaultAction, fmt.Errorf(`invalid target %q at line %d, must be a valid a CIDR, an IP address or "all"`, fields[1], lineNo)
				} else if strings.Contains(ip.String(), "%") {
					return nil, defaultAction, fmt.Errorf(`invalid target %q at line %d, must not contain "%%"`, fields[1], lineNo)
				}
				if ip.Is4() {
					target = netip.PrefixFrom(ip, 32)
				} else {
					target = netip.PrefixFrom(ip, 128)
				}
			} else if strings.Contains(target.String(), "%") {
				return nil, defaultAction, fmt.Errorf(`invalid target %q at line %d, must not contain "%%"`, fields[1], lineNo)
			}
			if defaultAction != Action(0) {
				return nil, defaultAction, fmt.Errorf(`target "all" line followed by non-"all" line at %d`, lineNo)
			}
			rules = append(rules, NewRule(target, action))
		}
	}
	if err := scanner.Err(); err != nil {
		return rules, defaultAction, err
	}
	if defaultAction == Action(0) {
		defaultAction = Allow
	}
	return rules, defaultAction, nil
}
