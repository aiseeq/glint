package patternkit

// EnclosingParen returns the offset of the innermost '(' that holds pos.
func (f JsFlat) EnclosingParen(pos int) (int, bool) {
	depth := 0
	for i := pos - 1; i >= 0; i-- {
		switch f.Code[i] {
		case ')':
			depth++
		case '(':
			if depth == 0 {
				return i, true
			}
			depth--
		case '{', '}', ';':
			if depth == 0 {
				return 0, false
			}
		}
	}
	return 0, false
}
