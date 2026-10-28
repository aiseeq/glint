package patternkit

import (
	"regexp"
)

// SmallPageFuncName names a function that wants a few rows on purpose.
var SmallPageFuncName = regexp.MustCompile(`(?i)recent|latest|newest|oldest|top|first|last|preview|sample|head|peek|exist|has|any|count`)
