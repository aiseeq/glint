package shellrules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
)

func TestCLIUnknownArgumentRunsDefaultAction(t *testing.T) {
	assert.Equal(t, []int{8}, patterntest.AppRuleLines(t, NewCLIUnknownArgumentRunsDefaultActionRule(), `package main

import "os"

const rebuildCommand = "rebuild"

func main() {
	if len(os.Args) > 1 && os.Args[1] == rebuildCommand {
		rebuild()
		return
	}
	serve()
}

func rebuild() {}
func serve() {}
`))
}

func TestCLIUnknownArgumentRunsDefaultActionAcrossPackageFiles(t *testing.T) {
	project := rulestest.Project(t, map[string]string{
		"main.go": `package main
import "os"
func main() {
	if len(os.Args) > 1 && os.Args[1] == rebuildCommand {
		rebuild()
		return
	}
	serve()
}
func rebuild() {}
func serve() {}
`,
		"commands.go": `package main
const rebuildCommand = "rebuild"
`,
	})
	violations, err := NewCLIUnknownArgumentRunsDefaultActionRule().AnalyzeGoProject(project)
	assert.NoError(t, err)
	assert.Len(t, violations, 1)
	assert.Equal(t, "main.go", violations[0].File)
	assert.Equal(t, 4, violations[0].Line)
}

func TestCLIUnknownArgumentRunsDefaultActionSwitch(t *testing.T) {
	assert.Equal(t, []int{6}, patterntest.AppRuleLines(t, NewCLIUnknownArgumentRunsDefaultActionRule(), `package main

import "os"

func main() {
	switch os.Args[1] {
	case "rebuild":
		rebuild()
		return
	}
	serve()
}

func rebuild() {}
func serve() {}
`))
}

func TestCLIUnknownArgumentRunsDefaultActionAcceptsPositionalInputs(t *testing.T) {
	for _, source := range []string{
		`package main

import "os"

func main() {
	if len(os.Args) == 4 && os.Args[1] == "-journal" {
		journal()
		return
	}
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	run(os.Args[1:])
}
func journal() {}
func usage() {}
func run([]string) {}
`,
		`package main

import (
	"flag"
	"os"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "recut" {
		recut()
		return
	}
	root := flag.String("root", ".", "root")
	flag.Parse()
	run(*root, flag.Args())
}
func recut() {}
func run(string, []string) {}
`,
		`package main

import "os"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-banes" {
		banes()
		return
	}
	load(os.Args[1])
}
func banes() {}
func load(string) {}
`,
	} {
		assert.Empty(t, patterntest.AppRuleLines(t, NewCLIUnknownArgumentRunsDefaultActionRule(), source))
	}
}

func TestCLIUnknownArgumentRunsDefaultActionAcceptsFlagPositionals(t *testing.T) {
	for _, source := range []string{
		`package main

import (
	"flag"
	"os"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "recut" {
		recut()
		return
	}
	flag.Parse()
	run(flag.Arg(0))
}
func recut() {}
func run(string) {}
`,
		`package main

import (
	"flag"
	"os"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "recut" {
		recut()
		return
	}
	flag.Parse()
	if flag.NArg() > 0 {
		run()
	}
}
func recut() {}
func run() {}
`,
	} {
		assert.Empty(t, patterntest.AppRuleLines(t, NewCLIUnknownArgumentRunsDefaultActionRule(), source))
	}
}

func TestCLIUnknownArgumentRunsDefaultActionParseOnlyStillReports(t *testing.T) {
	lines := patterntest.AppRuleLines(t, NewCLIUnknownArgumentRunsDefaultActionRule(), `package main

import (
	"flag"
	"os"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "recut" {
		recut()
		return
	}
	flag.Parse()
	serve()
}
func recut() {}
func serve() {}
`)
	assert.Equal(t, []int{9}, lines)
}

func TestCLIUnknownArgumentRunsDefaultActionReportsOnce(t *testing.T) {
	lines := patterntest.AppRuleLines(t, NewCLIUnknownArgumentRunsDefaultActionRule(), `package main

import "os"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "council" {
		council()
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "postpass" {
		postpass()
		return
	}
	run()
}
func council() {}
func postpass() {}
func run() {}
`)
	assert.Equal(t, []int{6}, lines)
}

func TestCLIUnknownArgumentRunsDefaultActionAccepts(t *testing.T) {
	for _, source := range []string{
		`package main

import "os"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "rebuild":
			rebuild()
			return
		default:
			os.Exit(2)
		}
	}
	serve()
}

func rebuild() {}
func serve() {}
`,
		`package main

import "os"

func main() {
	if len(os.Args) > 1 {
		os.Exit(2)
	}
	serve()
}

func serve() {}
`,
		`package main

import "os"

func main() {
	switch os.Args[1] {
	case "serve":
		serve()
	case "rebuild":
		rebuild()
	default:
		os.Exit(2)
	}
}

func serve() {}
func rebuild() {}
`,
		// A branch that ends waiting on a channel is no exit and must not crash the rule.
		`package main

import "os"

func main() {
	done := make(chan struct{})
	if os.Args[1] == "wait" {
		<-done
	}
	serve()
}

func serve() {}
`,
	} {
		assert.Empty(t, patterntest.AppRuleLines(t, NewCLIUnknownArgumentRunsDefaultActionRule(), source))
	}
}
