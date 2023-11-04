package ipacl

import (
	"log"
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
	b := newBinarySearchBuilder(rules, defaultAction)
	return b.toBinarySearch()
}

func (s *BinarySearch) Lookup(ip netip.Addr) Action {
	if ip.Is4() {
		target := v4AddrFromBytes(ip.As4())
		if len(s.v4EndAddrs) > 0 {
			i, _ := target.BinarySearch(s.v4EndAddrs)
			if i < len(s.v4StartAddrs) && target >= s.v4StartAddrs[i] {
				return s.action
			}
		}
		return s.action.Negated()
	}

	target := v6AddrFromBytes(ip.As16())
	if len(s.v6EndAddrs) > 0 {
		i, _ := target.BinarySearch(s.v6EndAddrs)
		if i < len(s.v6StartAddrs) && target.Compare(s.v6StartAddrs[i]) >= 0 {
			return s.action
		}
	}
	return s.action.Negated()
}

func (s *BinarySearch) String() string {
	var b strings.Builder
	b.WriteString("BinarySearch{v4:[")
	for i := range s.v4StartAddrs {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(s.v4StartAddrs[i].String())
		b.WriteByte('-')
		b.WriteString(s.v4EndAddrs[i].String())
	}
	b.WriteString("], v6:[")
	for i := range s.v6StartAddrs {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(s.v6StartAddrs[i].String())
		b.WriteByte('-')
		b.WriteString(s.v6EndAddrs[i].String())
	}
	b.WriteString("], action:")
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

func newBinarySearchBuilder(rules []Rule, defaultAction Action) binarySearchBuilder {
	b := binarySearchBuilder{
		defaultAction: defaultAction,
	}
	for _, rule := range rules {
		b.insertRule(rule)
	}
	return b
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

const debug = true

func (b *binarySearchBuilder) insertRule(rule Rule) {
	if rule.target.Addr().Is4() {
		b.insertRuleV4(rule)
	} else {
		b.insertRuleV6(rule)
	}
	if debug {
		log.Printf("insertRule exit, b=%s", b.String())
	}
}

func (b *binarySearchBuilder) insertRuleV4(rule Rule) {
	r := v4RangeFromPrefix(rule.target)
	if debug {
		log.Printf("insertRuleV4 start, %s", ruleRangeV4FromCIDR(rule))
	}
	if len(b.v4StartAddrs) == 0 {
		b.insertNonOverlapRangeV4(0, r.start, r.end, rule.action)
		return
	}

	i, _ := r.start.BinarySearch(b.v4StartAddrs)
	if debug {
		log.Printf("insertRuleV4 BinarySearch i=%d, len=%d", i, len(b.v4StartAddrs))
	}

	// Search already registered ranges until r.end.
	// Note: len(b.v4StartAddrs) may change in the following loop.
	for i < len(b.v4StartAddrs) {
		if debug {
			log.Printf("insertRule for loop, i=%d, len=%d, r=%s, b=%s", i, len(b.v4StartAddrs), r, b.String())
		}
		j, seenOtherAction := b.scanTillOtherActionV4(i, r.end, rule.action)
		jRange := v4Range{start: b.v4StartAddrs[j], end: b.v4EndAddrs[j]}
		if debug {
			log.Printf("insertRuleV4 j=%d, seenOtherAction=%v, jRange=%s", j, seenOtherAction, jRange)
		}
		if seenOtherAction {
			if r.Overlaps(jRange) {
				// found ranges of same action which overlaps my range before a range of different action.
				iRange := v4Range{start: b.v4StartAddrs[i], end: b.v4EndAddrs[i]}
				end := r.end.Min(jRange.start.Prev())
				if debug {
					log.Printf("insertRuleV4 diff action, overlap, iRange=%s, end=%s", iRange, end)
				}
				if j-1 > i && (r.Overlaps(iRange) || r.IsNeighbor(iRange)) {
					if r.start.Compare(b.v4StartAddrs[i]) < 0 {
						b.v4StartAddrs[i] = r.start
					}
					if end.Compare(b.v4EndAddrs[i]) > 0 {
						b.v4EndAddrs[i] = end
					}
					nDeleded := b.mayDeleteRangesV4(i+1, j)
					i = j + 1 - nDeleded
				} else {
					b.insertNonOverlapRangeV4(i, r.start, end, rule.action)
					i = j + 2
				}

				r.start = jRange.end.Next()
				if debug {
					log.Printf("insertRuleV4 updated i=%d, len=%d, r=%s", i, len(b.v4StartAddrs), r)
				}
				if r.start.Compare(r.end) > 0 || r.start.IsFirst() {
					return
				}
			} else {
				if debug {
					log.Print("insertRuleV4 diff action, no overlap")
				}
				// found ranges of same action which overlaps my range before a range of different action.
				if j-1 > i {
					if r.start.Compare(b.v4StartAddrs[i]) < 0 {
						b.v4StartAddrs[i] = r.start
					}
					if r.end.Compare(b.v4EndAddrs[i]) > 0 {
						b.v4EndAddrs[i] = r.end
					}
					b.mayDeleteRangesV4(i+1, j)
				} else {
					b.insertNonOverlapRangeV4(i, r.start, r.end, rule.action)
				}
				return
			}
		} else {
			if j == i && !(r.Overlaps(jRange) || r.IsNeighbor(jRange)) {
				b.insertNonOverlapRangeV4(i, r.start, r.end, rule.action)
			} else {
				if r.start.Compare(b.v4StartAddrs[i]) < 0 {
					b.v4StartAddrs[i] = r.start
				}
				if !(r.Overlaps(jRange) || r.IsNeighbor(jRange)) {
					j--
				}
				end := r.end.Max(b.v4EndAddrs[j])
				if end.Compare(b.v4EndAddrs[i]) > 0 {
					b.v4EndAddrs[i] = end
				}
				b.mayDeleteRangesV4(i+1, j+1)
			}
			return
		}
	}

	j := len(b.v4StartAddrs) - 1
	lastRange := v4Range{start: b.v4StartAddrs[j], end: b.v4EndAddrs[j]}
	if debug {
		log.Printf("insertRuleV4 lastRange=%s, lastAction=%s", lastRange, b.v4Actions[j])
	}
	if lastRange.Contains(r) {
		return
	}
	if rule.action == b.v4Actions[j] {
		if r.Overlaps(lastRange) || r.IsNeighbor(lastRange) {
			if r.start.Compare(b.v4StartAddrs[j]) < 0 {
				b.v4StartAddrs[j] = r.start
			}
			if r.end.Compare(b.v4EndAddrs[j]) > 0 {
				b.v4EndAddrs[j] = r.end
			}
			return
		}
	} else if r.Overlaps(lastRange) {
		if r.end.Compare(lastRange.end) < 0 {
			if debug {
				log.Print("insertRuleV4 diff action, overlap case#1")
			}
			b.insertNonOverlapRangeV4(i, r.start, lastRange.start.Prev(), rule.action)
		} else if r.start.Compare(lastRange.start) > 0 {
			if debug {
				log.Print("insertRuleV4 diff action, overlap case#2")
			}
			b.insertNonOverlapRangeV4(i, lastRange.end.Next(), r.end, rule.action)
		} else { // r.Contains(lastRange)
			if debug {
				log.Print("insertRuleV4 diff action, overlap case#3")
			}
			if r.start.Compare(lastRange.start) < 0 {
				b.insertNonOverlapRangeV4(i, r.start, lastRange.start.Prev(), rule.action)
			}
			if r.end.Compare(lastRange.end) > 0 {
				b.insertNonOverlapRangeV4(i, lastRange.end.Next(), r.end, rule.action)
			}
		}
		return
	}
	if debug {
		log.Print("insertRuleV4 diff action, no overlap")
	}
	b.insertNonOverlapRangeV4(i, r.start, r.end, rule.action)
}

func (b *binarySearchBuilder) scanTillOtherActionV4(i int, rangeEnd v4Addr, action Action) (j int, seenOtherAction bool) {
	if debug {
		log.Printf("scanTillOtherAction start i=%d, rangeEnd=%s, action=%s", i, rangeEnd, action)
	}
	for ; i < len(b.v4StartAddrs); i++ {
		if debug {
			log.Printf("scanTillOtherAction i=%d, start[i].prev=%s, action[i]=%s", i, b.v4StartAddrs[i].Prev(), b.v4Actions[i])
		}
		if action != b.v4Actions[i] {
			return i, true
		}
		if rangeEnd.Compare(b.v4StartAddrs[i].Prev()) < 0 {
			return i, false
		}
	}
	return len(b.v4StartAddrs) - 1, false
}

func (b *binarySearchBuilder) insertNonOverlapRangeV4(i int, start, end v4Addr, action Action) {
	b.v4StartAddrs = slices.Insert(b.v4StartAddrs, i, start)
	b.v4EndAddrs = slices.Insert(b.v4EndAddrs, i, end)
	b.v4Actions = slices.Insert(b.v4Actions, i, action)
}

func (b *binarySearchBuilder) mayDeleteRangesV4(i, j int) int {
	if i >= j {
		return 0
	}
	b.v4StartAddrs = slices.Delete(b.v4StartAddrs, i, j)
	b.v4EndAddrs = slices.Delete(b.v4EndAddrs, i, j)
	b.v4Actions = slices.Delete(b.v4Actions, i, j)
	if debug {
		log.Printf("mayDeleteRangesV4 deleted items n=%d", j-i)
	}
	return j - i
}

func (b *binarySearchBuilder) insertRuleV6(rule Rule) {
	r := v6RangeFromPrefix(rule.target)
	if debug {
		log.Printf("insertRuleV6 start, start=%s, end=%s, action=%s", r.start, r.end, rule.action)
	}
	if len(b.v6StartAddrs) == 0 {
		b.insertV6NoOverlap(0, r.start, r.end, rule.action)
		return
	}

	i, _ := r.start.BinarySearch(b.v6StartAddrs)
	if debug {
		log.Printf("insertRuleV6 BinarySearch i=%d, len=%d", i, len(b.v6StartAddrs))
	}
	for i < len(b.v6StartAddrs) {
		if r.start.Compare(b.v6StartAddrs[i]) < 0 {
			if debug {
				log.Printf("insertRuleV6 end=%s, start[i]=%s, action[i]=%s", r.end, b.v6StartAddrs[i], b.v6Actions[i])
			}
			if r.end.Compare(b.v6StartAddrs[i].Prev()) < 0 {
				b.insertV6NoOverlap(i, r.start, r.end, rule.action)
				return
			}
			if rule.action == b.v6Actions[i] {
				b.v6StartAddrs[i] = r.start
				seenOtherAction := false
				endNext := r.end.Next()
				j := i + 1
				for j < len(b.v6StartAddrs) {
					if rule.action == b.v6Actions[j] {
						if endNext.Compare(b.v6StartAddrs[j]) >= 0 || endNext.IsFirst() {
							j++
						} else {
							break
						}
					} else {
						seenOtherAction = true
						break
					}
				}
				if debug {
					log.Printf("insertRuleV6 j=%d, seenOtherAction=%v", j, seenOtherAction)
				}
				if seenOtherAction {
					if debug {
						log.Printf("insertRuleV6 seenOhterAction, r.end=%s, start[j]=%s", r.end, b.v6StartAddrs[j])
					}
					b.v6EndAddrs[i] = r.end.Max(b.v6EndAddrs[j-1]).Min(b.v6StartAddrs[j].Prev())
				} else {
					if j < len(b.v6EndAddrs) {
						if endNext.Compare(b.v6StartAddrs[j]) < 0 {
							b.v6EndAddrs[i] = r.end.Max(b.v6EndAddrs[j-1])
							if debug {
								log.Printf("insertRuleV6 updated#1 end[i]=%s", b.v6EndAddrs[i])
							}
						} else {
							b.v6EndAddrs[i] = r.end.Max(b.v6EndAddrs[j])
							if debug {
								log.Printf("insertRuleV6 updated#2 end[i]=%s", b.v6EndAddrs[i])
							}
						}
					} else if r.end.Compare(b.v6EndAddrs[i]) > 0 {
						b.v6EndAddrs[i] = r.end
						if debug {
							log.Printf("insertRuleV6 updated#3 end[i]=%s", b.v6EndAddrs[i])
						}
					}
				}
				if j > i+1 {
					b.deleteV6Ranges(i+1, j)
				}
			} else {
				b.insertV6NoOverlap(i, r.start, b.v6StartAddrs[i].Prev(), rule.action)
			}
		}

		r.start = b.v6EndAddrs[i].Next()
		if r.start.Compare(r.end) > 0 || r.start.IsFirst() {
			return
		}
		i++
	}
	j := len(b.v6StartAddrs) - 1
	lastRange := v6Range{start: b.v6StartAddrs[j], end: b.v6EndAddrs[j]}
	if debug {
		log.Printf("insertRuleV6 lastRange={%s-%s}, lastAction=%s, r={%s-%s}, rAction=%s, overlaps=%v, contains=%v",
			lastRange.start, lastRange.end, b.v6Actions[j], r.start, r.end, rule.action, r.Overlaps(lastRange), r.IsNeighbor(lastRange))
	}
	if lastRange.Contains(r) {
		return
	}
	if rule.action == b.v6Actions[j] {
		if r.Overlaps(lastRange) || r.IsNeighbor(lastRange) {
			if r.end.Compare(b.v6EndAddrs[j]) > 0 {
				b.v6EndAddrs[j] = r.end
			}
			return
		}
	} else if r.Overlaps(lastRange) {
		if r.start.Compare(b.v6EndAddrs[j]) <= 0 {
			r.start = b.v6EndAddrs[j].Next()
		}
	}
	b.insertV6NoOverlap(i, r.start, r.end, rule.action)
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
	sb.WriteString("binarySearchBuilder{v4:[")
	for i := range b.v4StartAddrs {
		if i > 0 {
			sb.WriteString(", ")
		}
		if b.v4Actions[i] == Deny {
			sb.WriteByte('!')
		}
		sb.WriteString(b.v4StartAddrs[i].String())
		if b.v4EndAddrs[i].Compare(b.v4StartAddrs[i]) != 0 {
			sb.WriteByte('-')
			sb.WriteString(b.v4EndAddrs[i].String())
		}
	}
	sb.WriteString("], v6:[")
	for i := range b.v6StartAddrs {
		if i > 0 {
			sb.WriteString(", ")
		}
		if b.v6Actions[i] == Deny {
			sb.WriteByte('!')
		}
		sb.WriteString(b.v6StartAddrs[i].String())
		if b.v6EndAddrs[i].Compare(b.v6StartAddrs[i]) != 0 {
			sb.WriteByte('-')
			sb.WriteString(b.v6EndAddrs[i].String())
		}
	}
	sb.WriteString("], defaultAction:")
	sb.WriteString(b.defaultAction.String())
	sb.WriteByte('}')
	return sb.String()
}
