package patternkit

// NamedEnclosingFunction returns the innermost named function around pos,
// past the anonymous callbacks inside it.
func NamedEnclosingFunction(f JsFlat, pos int) (JsFunc, bool) {
	fn, ok := f.EnclosingFunction(pos)
	for ok && fn.Name == "" {
		fn, ok = f.EnclosingFunction(fn.Start)
	}
	return fn, ok
}
