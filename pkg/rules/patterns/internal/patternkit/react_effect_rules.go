package patternkit

// ExpressionEnd returns where the expression that starts at pos ends: the
// first ';', line end or unbalanced closing bracket outside brackets, or
// limit.
func (f JsFlat) ExpressionEnd(pos, limit int) int {
	depth := 0
	for i := pos; i < limit; i++ {
		switch f.Code[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth == 0 {
				return i
			}
			depth--
		case ';', '\n':
			if depth == 0 {
				return i
			}
		}
	}
	return limit
}
