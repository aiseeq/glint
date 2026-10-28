package patternkit

// IsWordChar mirrors regexp's \w class: [0-9A-Za-z_].
func IsWordChar(b byte) bool {
	return b == '_' ||
		(b >= '0' && b <= '9') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= 'a' && b <= 'z')
}
