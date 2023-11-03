package ipacl

import (
	"net/netip"
	"slices"
	"strings"
)

type BinarySearch struct {
	v4StartAddrs []v4Addr
	v4EndAddrs   []v4Addr

	v6StartAddrs []v6Addr
	v6EndAddrs   []v6Addr

	action Action
}

func NewBinarySearch(rules []Rule, defaultAction Action) BinarySearch {
	b := binarySearchBuilder{
		defaultAction: defaultAction,
	}
	for _, rule := range rules {
		b.insertRule(rule)
	}
	return b.toBinarySearch()
}

func (s *BinarySearch) Lookup(ip netip.Addr) Action {
	if ip.Is4() {
		target := v4AddrFromBytes(ip.As4())
		i, _ := target.BinarySearch(s.v4EndAddrs)
		if i < len(s.v4StartAddrs) && target >= s.v4StartAddrs[i] {
			return s.action
		}
		return s.action.Negated()
	}

	target := v6AddrFromBytes(ip.As16())
	i, _ := target.BinarySearch(s.v6EndAddrs)
	if i < len(s.v6StartAddrs) && target.Compare(s.v6StartAddrs[i]) >= 0 {
		return s.action
	}
	return s.action.Negated()
}

func (s *BinarySearch) String() string {
	var b strings.Builder
	b.WriteString("BinarySearch{v4Rules: [")
	for i := range s.v4StartAddrs {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString("{start: ")
		b.WriteString(s.v4StartAddrs[i].String())
		b.WriteString(", end: ")
		b.WriteString(s.v4EndAddrs[i].String())
		b.WriteByte('}')
	}
	b.WriteString("], v6Rules: [")
	for i := range s.v6StartAddrs {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString("{start: ")
		b.WriteString(s.v6StartAddrs[i].String())
		b.WriteString(", end: ")
		b.WriteString(s.v6EndAddrs[i].String())
		b.WriteByte('}')
	}
	b.WriteString("], action: ")
	b.WriteString(s.action.String())
	b.WriteByte('}')
	return b.String()
}

type binarySearchBuilder struct {
	v4StartAddrs []v4Addr
	v4EndAddrs   []v4Addr
	v4Actions    []Action

	v6StartAddrs []v6Addr
	v6EndAddrs   []v6Addr
	v6Actions    []Action

	defaultAction Action
}

func (b *binarySearchBuilder) toBinarySearch() BinarySearch {
	s := BinarySearch{
		action: b.defaultAction.Negated(),
	}

	n := 0
	for _, a := range b.v4Actions {
		if a != b.defaultAction {
			n++
		}
	}
	s.v4StartAddrs = make([]v4Addr, n)
	s.v4EndAddrs = make([]v4Addr, n)
	j := 0
	for i, a := range b.v4Actions {
		if a != b.defaultAction {
			s.v4StartAddrs[j] = b.v4StartAddrs[i]
			s.v4EndAddrs[j] = b.v4EndAddrs[i]
			j++
		}
	}

	n = 0
	for _, a := range b.v6Actions {
		if a != b.defaultAction {
			n++
		}
	}
	s.v6StartAddrs = make([]v6Addr, n)
	s.v6EndAddrs = make([]v6Addr, n)
	j = 0
	for i, a := range b.v6Actions {
		if a != b.defaultAction {
			s.v6StartAddrs[j] = b.v6StartAddrs[i]
			s.v6EndAddrs[j] = b.v6EndAddrs[i]
			j++
		}
	}

	return s
}

func (b *binarySearchBuilder) insertRule(rule Rule) {
	if rule.Target.Addr().Is4() {
		b.insertRuleV4(rule)
	} else {
		b.insertRuleV6(rule)
	}
}

func (b *binarySearchBuilder) insertRuleV4(rule Rule) {
	r := v4RangeFromPrefix(rule.Target)
	// log.Printf("insertRuleV4 start, start=%s, end=%s, action=%s", r.start, r.end, rule.Action)
	if len(b.v4StartAddrs) == 0 {
		b.insertV4NoOverlap(0, r.start, r.end, rule.Action)
		return
	}

	i, _ := r.start.BinarySearch(b.v4StartAddrs)
	// log.Printf("insertRuleV4 BinarySearch i=%d, len=%d", i, len(b.v4StartAddrs))
	for i < len(b.v4StartAddrs) {
		if r.start.Compare(b.v4StartAddrs[i]) < 0 {
			endNext := r.end.Next()
			// log.Printf("insertRuleV4 endNext=%s, start[i]=%s, action[i]=%s", endNext, b.v4StartAddrs[i], b.v4Actions[i])
			if endNext.Compare(b.v4StartAddrs[i]) < 0 {
				b.insertV4NoOverlap(i, r.start, r.end, rule.Action)
				return
			}
			if rule.Action == b.v4Actions[i] {
				b.v4StartAddrs[i] = r.start
				seenOtherAction := false
				j := i + 1
				for j < len(b.v4StartAddrs) {
					if rule.Action == b.v4Actions[j] {
						if endNext.Compare(b.v4StartAddrs[j]) >= 0 {
							j++
						}
					} else {
						seenOtherAction = true
						break
					}
				}
				// log.Printf("insertRuleV4 j=%d, seenOtherAction=%v", j, seenOtherAction)
				if seenOtherAction {
					b.v4EndAddrs[i] = r.end.Min(b.v4StartAddrs[j].Prev())
				} else {
					if j < len(b.v4EndAddrs) {
						b.v4EndAddrs[i] = r.end.Max(b.v4EndAddrs[j])
					} else if r.end.Compare(b.v4EndAddrs[i]) > 0 {
						b.v4EndAddrs[i] = r.end
					}
				}
				if j > i+1 {
					b.deleteV4Ranges(i+1, j)
				}
			} else {
				b.insertV4NoOverlap(i, r.start, b.v4StartAddrs[i].Prev(), rule.Action)
			}
		}

		r.start = b.v4EndAddrs[i].Next()
		if r.start.Compare(r.end) > 0 || r.start.IsFirst() {
			return
		}
		i++
	}
	j := len(b.v4StartAddrs) - 1
	if rule.Action == b.v4Actions[j] && r.start.Compare(b.v4EndAddrs[j].Next()) <= 0 {
		if r.end.Compare(b.v4EndAddrs[j]) > 0 {
			b.v4EndAddrs[j] = r.end
		}
	} else {
		b.insertV4NoOverlap(i, r.start, r.end, rule.Action)
	}
}

func (b *binarySearchBuilder) insertV4NoOverlap(i int, start, end v4Addr, action Action) {
	b.v4StartAddrs = slices.Insert(b.v4StartAddrs, i, start)
	b.v4EndAddrs = slices.Insert(b.v4EndAddrs, i, end)
	b.v4Actions = slices.Insert(b.v4Actions, i, action)
}

func (b *binarySearchBuilder) deleteV4Ranges(i, j int) {
	b.v4StartAddrs = slices.Delete(b.v4StartAddrs, i, j)
	b.v4EndAddrs = slices.Delete(b.v4EndAddrs, i, j)
	b.v4Actions = slices.Delete(b.v4Actions, i, j)
}

func (b *binarySearchBuilder) insertRuleV6(rule Rule) {
	r := v6RangeFromPrefix(rule.Target)
	// log.Printf("insertRuleV6 start, start=%s, end=%s, action=%s", r.start, r.end, rule.Action)
	if len(b.v6StartAddrs) == 0 {
		b.insertV6NoOverlap(0, r.start, r.end, rule.Action)
		return
	}

	i, _ := r.start.BinarySearch(b.v6StartAddrs)
	// log.Printf("insertRuleV6 BinarySearch i=%d, len=%d", i, len(b.v6StartAddrs))
	for i < len(b.v6StartAddrs) {
		if r.start.Compare(b.v6StartAddrs[i]) < 0 {
			endNext := r.end.Next()
			// log.Printf("insertRuleV6 endNext=%s, start[i]=%s, action[i]=%s", endNext, b.v6StartAddrs[i], b.v6Actions[i])
			if endNext.Compare(b.v6StartAddrs[i]) < 0 {
				b.insertV6NoOverlap(i, r.start, r.end, rule.Action)
				return
			}
			if rule.Action == b.v6Actions[i] {
				b.v6StartAddrs[i] = r.start
				seenOtherAction := false
				j := i + 1
				for j < len(b.v6StartAddrs) {
					if rule.Action == b.v6Actions[j] {
						if endNext.Compare(b.v6StartAddrs[j]) >= 0 {
							j++
						}
					} else {
						seenOtherAction = true
						break
					}
				}
				// log.Printf("insertRuleV6 j=%d, seenOtherAction=%v", j, seenOtherAction)
				if seenOtherAction {
					b.v6EndAddrs[i] = r.end.Min(b.v6StartAddrs[j].Prev())
				} else {
					if j < len(b.v6EndAddrs) {
						b.v6EndAddrs[i] = r.end.Max(b.v6EndAddrs[j])
					} else if r.end.Compare(b.v6EndAddrs[i]) > 0 {
						b.v6EndAddrs[i] = r.end
					}
				}
				if j > i+1 {
					b.deleteV6Ranges(i+1, j)
				}
			} else {
				b.insertV6NoOverlap(i, r.start, b.v6StartAddrs[i].Prev(), rule.Action)
			}
		}

		r.start = b.v6EndAddrs[i].Next()
		if r.start.Compare(r.end) > 0 || r.start.IsFirst() {
			return
		}
		i++
	}
	j := len(b.v6StartAddrs) - 1
	if rule.Action == b.v6Actions[j] && r.start.Compare(b.v6EndAddrs[j].Next()) <= 0 {
		if r.end.Compare(b.v6EndAddrs[j]) > 0 {
			b.v6EndAddrs[j] = r.end
		}
	} else {
		b.insertV6NoOverlap(i, r.start, r.end, rule.Action)
	}
}

func (b *binarySearchBuilder) insertV6NoOverlap(i int, start, end v6Addr, action Action) {
	b.v6StartAddrs = slices.Insert(b.v6StartAddrs, i, start)
	b.v6EndAddrs = slices.Insert(b.v6EndAddrs, i, end)
	b.v6Actions = slices.Insert(b.v6Actions, i, action)
}

func (b *binarySearchBuilder) deleteV6Ranges(i, j int) {
	b.v6StartAddrs = slices.Delete(b.v6StartAddrs, i, j)
	b.v6EndAddrs = slices.Delete(b.v6EndAddrs, i, j)
	b.v6Actions = slices.Delete(b.v6Actions, i, j)
}

func (b *binarySearchBuilder) String() string {
	var sb strings.Builder
	sb.WriteString("binarySearchBuilder{v4Rules: [")
	for i := range b.v4StartAddrs {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString("{start: ")
		sb.WriteString(b.v4StartAddrs[i].String())
		sb.WriteString(", end: ")
		sb.WriteString(b.v4EndAddrs[i].String())
		sb.WriteString(", action: ")
		sb.WriteString(b.v4Actions[i].String())
		sb.WriteByte('}')
	}
	sb.WriteString("], v6Rules: [")
	for i := range b.v6StartAddrs {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString("{start: ")
		sb.WriteString(b.v6StartAddrs[i].String())
		sb.WriteString(", end: ")
		sb.WriteString(b.v6EndAddrs[i].String())
		sb.WriteString(", action: ")
		sb.WriteString(b.v6Actions[i].String())
		sb.WriteByte('}')
	}
	sb.WriteString("], defaultAction: ")
	sb.WriteString(b.defaultAction.String())
	sb.WriteByte('}')
	return sb.String()
}
