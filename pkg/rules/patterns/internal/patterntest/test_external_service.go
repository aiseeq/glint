package patterntest

import (
	"go/importer"
	"go/token"
)

// typedFile парсит и типизирует исходник: детектор исходящих вызовов работает по
// типам, иначе `once.Do(...)` из sync считался бы отправкой HTTP-запроса.
// stdImporter reads the standard library from export data once for every
// test of the package: a source importer per test would parse and check it
// again each time.
var StdImporter = importer.ForCompiler(token.NewFileSet(), "gc", nil)
