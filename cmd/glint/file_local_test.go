package main

import (
	"go/types"
	"reflect"
	"sort"
	"strings"
	"testing"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/callgraph/vta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"

	"github.com/aiseeq/glint/pkg/rules"
)

const glintModule = "github.com/aiseeq/glint/"

// outsideTheFile are the functions whose result depends on more than the
// analyzed file: the disk, the environment, the clock, chance.
var outsideTheFile = map[string]bool{
	"os.Stat": true, "os.Lstat": true, "os.Open": true, "os.OpenFile": true,
	"os.ReadFile": true, "os.ReadDir": true, "os.Readlink": true, "os.DirFS": true,
	"os.Getenv": true, "os.LookupEnv": true, "os.Environ": true, "os.Getwd": true,
	"os.Hostname": true, "os.Executable": true,
	"path/filepath.Glob": true, "path/filepath.Walk": true, "path/filepath.WalkDir": true,
	"path/filepath.EvalSymlinks": true, "path/filepath.Abs": true,
	"io/fs.ReadFile": true, "io/fs.ReadDir": true, "io/fs.Glob": true, "io/fs.WalkDir": true,
	"io/fs.Stat": true, "io/ioutil.ReadFile": true, "io/ioutil.ReadDir": true,
	"os/exec.Command": true, "os/exec.CommandContext": true,
	"time.Now": true, "time.Since": true, "time.Until": true,
	"net.Dial": true, "net.DialTimeout": true, "net.Listen": true, "net.LookupHost": true,
	"net.LookupIP": true, "net/http.Get": true, "net/http.Post": true, "net/http.Head": true,
}

// outsidePackages are packages every function of which reaches outside.
var outsidePackages = []string{"math/rand", "crypto/rand"}

// A file-local rule's findings are reused while the file is unchanged. Its
// AnalyzeFile must therefore reach nothing that depends on other files or on
// the moment of the run; a rule that does declares ReadsOtherFiles.
func TestFileLocalRulesReachNothingOutsideTheirFile(t *testing.T) {
	if testing.Short() {
		t.Skip("loads and builds SSA for every rule package")
	}
	loaded, err := packages.Load(&packages.Config{
		Mode: packages.LoadAllSyntax,
		Dir:  "../..",
	}, "./pkg/rules/...")
	if err != nil {
		t.Fatalf("load rule packages: %v", err)
	}
	if packages.PrintErrors(loaded) > 0 {
		t.Fatal("rule packages do not type-check")
	}
	program, _ := ssautil.AllPackages(loaded, ssa.InstantiateGenerics)
	program.Build()
	// CHA resolves a call of a function value to every function of the same
	// signature; VTA refines it to the values that can flow there.
	graph := vta.CallGraph(ssautil.AllFunctions(program), cha.CallGraph(program))

	checked := 0
	for _, rule := range rules.All() {
		if !rules.FileLocal(rule) {
			continue
		}
		analyze := analyzeFileMethod(t, program, rule)
		if path := pathOutside(graph, analyze); path != nil {
			t.Errorf("file-local rule %s reaches %s; declare ReadsOtherFiles or drop the call",
				rule.Name(), strings.Join(path, " -> "))
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no file-local rule was checked")
	}
}

// analyzeFileMethod finds the SSA function of the rule's AnalyzeFile method.
func analyzeFileMethod(t *testing.T, program *ssa.Program, rule rules.Rule) *ssa.Function {
	t.Helper()
	ruleType := reflect.TypeOf(rule)
	if ruleType.Kind() != reflect.Pointer {
		t.Fatalf("rule %s is not a pointer to a named type", rule.Name())
	}
	pkg := program.ImportedPackage(ruleType.Elem().PkgPath())
	if pkg == nil {
		t.Fatalf("rule %s: package %s is not loaded", rule.Name(), ruleType.Elem().PkgPath())
	}
	member, ok := pkg.Members[ruleType.Elem().Name()].(*ssa.Type)
	if !ok {
		t.Fatalf("rule %s: type %s not found", rule.Name(), ruleType.Elem().Name())
	}
	selection := program.MethodSets.MethodSet(types.NewPointer(member.Type())).Lookup(nil, "AnalyzeFile")
	if selection == nil {
		t.Fatalf("rule %s has no AnalyzeFile method", rule.Name())
	}
	return program.MethodValue(selection)
}

// pathOutside walks the call graph from start through the module's own code
// and returns the first call chain that ends outside the file, or nil.
func pathOutside(graph *callgraph.Graph, start *ssa.Function) []string {
	parent := map[*ssa.Function]*ssa.Function{start: nil}
	queue := []*ssa.Function{start}
	for len(queue) > 0 {
		fn := queue[0]
		queue = queue[1:]
		node := graph.Nodes[fn]
		if node == nil {
			continue
		}
		edges := append([]*callgraph.Edge(nil), node.Out...)
		sort.Slice(edges, func(i, j int) bool { return edges[i].Callee.Func.String() < edges[j].Callee.Func.String() })
		for _, edge := range edges {
			callee := edge.Callee.Func
			if _, seen := parent[callee]; seen {
				continue
			}
			parent[callee] = fn
			if reachesOutside(callee) {
				return callChain(parent, callee)
			}
			if strings.HasPrefix(functionPackage(callee), glintModule) {
				queue = append(queue, callee)
			}
		}
	}
	return nil
}

func reachesOutside(fn *ssa.Function) bool {
	pkg := functionPackage(fn)
	for _, outside := range outsidePackages {
		if pkg == outside || strings.HasPrefix(pkg, outside+"/") {
			return true
		}
	}
	return outsideTheFile[pkg+"."+fn.Name()] && fn.Signature.Recv() == nil
}

// functionPackage is the path of the package that declares fn, following
// generic instances and wrappers to their origin.
func functionPackage(fn *ssa.Function) string {
	if origin := fn.Origin(); origin != nil {
		fn = origin
	}
	if fn.Pkg != nil {
		return fn.Pkg.Pkg.Path()
	}
	if obj := fn.Object(); obj != nil && obj.Pkg() != nil {
		return obj.Pkg().Path()
	}
	return ""
}

func callChain(parent map[*ssa.Function]*ssa.Function, last *ssa.Function) []string {
	var chain []string
	for fn := last; fn != nil; fn = parent[fn] {
		chain = append([]string{fn.String()}, chain...)
	}
	return chain
}
