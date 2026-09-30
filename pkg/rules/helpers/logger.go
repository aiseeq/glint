package helpers

import (
	"go/ast"
	"strings"
)

// IsLoggerCall recognises calls on a logger: the receiver mentions log (log, logger,
// slog, zlog, r.logger, logging.X) or is a known logging package, and the method is a
// logging verb. fmt.Print* is not a logger: on a CLI stdout is the caller.
func IsLoggerCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if IsStderrPrint(sel, call) {
		return true
	}
	verb := LogVerb(sel)
	if !loggingVerbs[verb] && !strings.HasPrefix(verb, "log") {
		return false
	}
	// A method named log or logf says what it does whatever its receiver
	// is called (c.log(...)); the math packages' Log is a logarithm.
	if (verb == "log" || verb == "logf") && !isMathPackage(sel.X) {
		return true
	}
	return IsLoggerReceiver(sel.X)
}

// IsStderrPrint reports fmt.Fprint, Fprintf or Fprintln to os.Stderr: the log
// of a command-line tool.
func IsStderrPrint(sel *ast.SelectorExpr, call *ast.CallExpr) bool {
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "fmt" || !strings.HasPrefix(sel.Sel.Name, "Fprint") || len(call.Args) == 0 {
		return false
	}
	stream, ok := ast.Unparen(call.Args[0]).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	osPkg, ok := stream.X.(*ast.Ident)
	return ok && osPkg.Name == "os" && stream.Sel.Name == "Stderr"
}

func isMathPackage(expr ast.Expr) bool {
	ident, ok := ast.Unparen(expr).(*ast.Ident)
	return ok && (ident.Name == "math" || ident.Name == "cmplx")
}

// LogVerb returns the method name of a logging call in lower case, without
// the Structured/Context suffix of structured loggers: ErrorStructured and
// WarnContext are error and warn.
func LogVerb(sel *ast.SelectorExpr) string {
	verb := strings.ToLower(sel.Sel.Name)
	return strings.TrimSuffix(strings.TrimSuffix(verb, "structured"), "context")
}

// IsLoggerReceiver reports whether the receiver of a call is a logger: its
// text mentions log (log, logger, slog, zlog, r.logger, logging.X) or it is a
// known logging package.
func IsLoggerReceiver(expr ast.Expr) bool {
	// A logger a factory returns — logging.Get().Error(...) — is named by the
	// factory.
	if call, ok := ast.Unparen(expr).(*ast.CallExpr); ok {
		expr = call.Fun
	}
	receiver := strings.ToLower(ExprText(expr))
	return strings.Contains(receiver, "log") ||
		strings.HasPrefix(receiver, "zap") || strings.HasPrefix(receiver, "logrus") ||
		strings.HasPrefix(receiver, "zerolog") || strings.HasPrefix(receiver, "slog") ||
		strings.HasPrefix(receiver, "sentry") || strings.HasPrefix(receiver, "span")
}

var loggingVerbs = map[string]bool{
	"error": true, "errorf": true, "errorw": true, "errorln": true,
	"warn": true, "warnf": true, "warnw": true, "warning": true, "warningf": true,
	"info": true, "infof": true, "infow": true,
	"debug": true, "debugf": true, "debugw": true,
	"trace": true, "tracef": true,
	"print": true, "printf": true, "println": true,
	"log": true, "logf": true,
	"capture": true, "captureexception": true, "capturemessage": true, "recorderror": true,
}

// ExprText renders an identifier chain (x, x.y, x.y.z) as text. An empty string means
// the expression is more than a chain of fields and is not matched by text.
func ExprText(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		base := ExprText(e.X)
		if base == "" {
			return ""
		}
		return base + "." + e.Sel.Name
	case *ast.ParenExpr:
		return ExprText(e.X)
	default:
		return ""
	}
}
