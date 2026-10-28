package patternkit

// JsxElement returns the span of the JSX opening tag that holds pos: from
// its '<' to the '>' that ends it, outside the braces of its attributes.
func (f JsFlat) JsxElement(pos int) (int, int, bool) {
	start := -1
	for i := pos; i > 0; i-- {
		if f.Code[i] == '<' && i+1 < len(f.Code) && IsASCIILetter(f.Code[i+1]) {
			start = i
			break
		}
		if f.Code[i] == '>' || f.Code[i] == ';' {
			return 0, 0, false
		}
	}
	if start < 0 {
		return 0, 0, false
	}
	depth := 0
	for i := start + 1; i < len(f.Code); i++ {
		switch f.Code[i] {
		case '{':
			depth++
		case '}':
			depth--
		case '>':
			if depth == 0 {
				return start, i + 1, true
			}
		}
	}
	return 0, 0, false
}
