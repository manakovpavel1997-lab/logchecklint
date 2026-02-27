package analyzer

import (
	"go/ast"
	"go/token"
	"strings"
	"unicode"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

// Config holds the linter configuration.
type Config struct {
	// DisableLowercaseCheck disables the lowercase start rule.
	DisableLowercaseCheck bool `json:"disable_lowercase_check"`
	// DisableEnglishCheck disables the English-only rule.
	DisableEnglishCheck bool `json:"disable_english_check"`
	// DisableSpecialCharCheck disables the special characters/emoji rule.
	DisableSpecialCharCheck bool `json:"disable_special_char_check"`
	// DisableSensitiveCheck disables the sensitive data rule.
	DisableSensitiveCheck bool `json:"disable_sensitive_check"`
	// CustomSensitiveKeywords is a list of additional keywords to check.
	CustomSensitiveKeywords []string `json:"custom_sensitive_keywords"`
}

// Analyzer is the logchecklint analyzer.
var Analyzer = &analysis.Analyzer{
	Name:     "logchecklint",
	Doc:      "checks log messages for common issues: uppercase start, non-English text, special characters, sensitive data",
	Run:      run,
	Requires: []*analysis.Analyzer{inspect.Analyzer},
}

// logFunctions maps package paths to their logging function names.
var logFunctions = map[string]map[string]bool{
	// log/slog package
	"log/slog": {
		"Info":  true,
		"Error": true,
		"Warn":  true,
		"Debug": true,
		"Log":   true,
	},
	// slog top-level functions
	"slog": {
		"Info":  true,
		"Error": true,
		"Warn":  true,
		"Debug": true,
		"Log":   true,
	},
}

// zapMethods contains zap logger method names that accept a message string.
var zapMethods = map[string]bool{
	"Info":   true,
	"Error":  true,
	"Warn":   true,
	"Debug":  true,
	"Fatal":  true,
	"Panic":  true,
	"DPanic": true,
	// SugaredLogger methods
	"Infof":   true,
	"Errorf":  true,
	"Warnf":   true,
	"Debugf":  true,
	"Fatalf":  true,
	"Panicf":  true,
	"DPanicf": true,
	"Infow":   true,
	"Errorw":  true,
	"Warnw":   true,
	"Debugw":  true,
	"Fatalw":  true,
	"Panicw":  true,
	"DPanicw": true,
}

func run(pass *analysis.Pass) (interface{}, error) {
	insp := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)

	nodeFilter := []ast.Node{
		(*ast.CallExpr)(nil),
	}

	insp.Preorder(nodeFilter, func(n ast.Node) {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return
		}

		msg, pos := extractLogMessage(call)
		if msg == "" {
			return
		}

		checkAndReport(pass, msg, pos)
	})

	return nil, nil
}

// RunWithConfig runs the analyzer with the given configuration.
func RunWithConfig(cfg Config) func(*analysis.Pass) (interface{}, error) {
	return func(pass *analysis.Pass) (interface{}, error) {
		insp := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)

		nodeFilter := []ast.Node{
			(*ast.CallExpr)(nil),
		}

		insp.Preorder(nodeFilter, func(n ast.Node) {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return
			}

			msg, pos := extractLogMessage(call)
			if msg == "" {
				return
			}

			checkAndReportWithConfig(pass, msg, pos, cfg)
		})

		return nil, nil
	}
}

// extractLogMessage tries to extract the log message string from a call expression.
// It supports slog.Info("msg"), logger.Info("msg"), zap.L().Info("msg"), etc.
func extractLogMessage(call *ast.CallExpr) (string, token.Pos) {
	if len(call.Args) == 0 {
		return "", token.NoPos
	}

	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		funcName := fn.Sel.Name

		// Check if it's a slog function: slog.Info("msg")
		if ident, ok := fn.X.(*ast.Ident); ok {
			if ident.Name == "slog" {
				if _, exists := logFunctions["slog"][funcName]; exists {
					return extractStringArg(call, funcName)
				}
			}
			// Check for logger variable methods: logger.Info("msg")
			if zapMethods[funcName] {
				return extractStringArg(call, funcName)
			}
		}

		// Check for chained calls: zap.L().Info("msg"), sugar.Infow("msg")
		if _, ok := fn.X.(*ast.CallExpr); ok {
			if zapMethods[funcName] {
				return extractStringArg(call, funcName)
			}
		}

		// Check for log.Info, log.Error, etc. (generic "log" package)
		if ident, ok := fn.X.(*ast.Ident); ok {
			if ident.Name == "log" {
				switch funcName {
				case "Info", "Error", "Warn", "Debug", "Fatal", "Panic",
					"Infof", "Errorf", "Warnf", "Debugf", "Fatalf", "Panicf":
					return extractStringArg(call, funcName)
				}
			}
		}
	}

	return "", token.NoPos
}

// extractStringArg extracts the first string literal argument from a call expression.
// For slog.Log, the message is at index 1 (after context and level), for others at index 0.
func extractStringArg(call *ast.CallExpr, funcName string) (string, token.Pos) {
	// For slog.Log, first arg is context, second is level, third is message
	if funcName == "Log" && len(call.Args) >= 3 {
		if lit, ok := call.Args[2].(*ast.BasicLit); ok && lit.Kind == token.STRING {
			return strings.Trim(lit.Value, "`\"" ), lit.Pos()
		}
		return "", token.NoPos
	}

	// For other functions, check first argument
	if len(call.Args) >= 1 {
		if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
			return strings.Trim(lit.Value, "`\""), lit.Pos()
		}
	}

	return "", token.NoPos
}

func checkAndReport(pass *analysis.Pass, msg string, pos token.Pos) {
	if CheckLowercaseStart(msg) {
		lower := strings.ToLower(string(msg[0])) + msg[1:]
		pass.Report(analysis.Diagnostic{
			Pos:      pos,
			Message:  "log message should start with a lowercase letter",
			Category: "logchecklint",
			SuggestedFixes: []analysis.SuggestedFix{
				{
					Message: "convert first letter to lowercase",
					TextEdits: []analysis.TextEdit{
						{
							Pos:     pos,
							End:     pos + token.Pos(len(msg)+2), // +2 for quotes
							NewText: []byte(`"` + lower + `"`),
						},
					},
				},
			},
		})
	}

	if CheckEnglishOnly(msg) {
		pass.Reportf(pos, "log message should be in English only")
	}

	if CheckSpecialCharsOrEmoji(msg) {
		cleaned := cleanSpecialChars(msg)
		pass.Report(analysis.Diagnostic{
			Pos:      pos,
			Message:  "log message should not contain special characters or emoji",
			Category: "logchecklint",
			SuggestedFixes: []analysis.SuggestedFix{
				{
					Message: "remove special characters and emoji",
					TextEdits: []analysis.TextEdit{
						{
							Pos:     pos,
							End:     pos + token.Pos(len(msg)+2),
							NewText: []byte(`"` + cleaned + `"`),
						},
					},
				},
			},
		})
	}

	if CheckSensitiveData(msg) {
		pass.Reportf(pos, "log message may contain sensitive data")
	}
}

func checkAndReportWithConfig(pass *analysis.Pass, msg string, pos token.Pos, cfg Config) {
	if !cfg.DisableLowercaseCheck && CheckLowercaseStart(msg) {
		pass.Reportf(pos, "log message should start with a lowercase letter")
	}

	if !cfg.DisableEnglishCheck && CheckEnglishOnly(msg) {
		pass.Reportf(pos, "log message should be in English only")
	}

	if !cfg.DisableSpecialCharCheck && CheckSpecialCharsOrEmoji(msg) {
		pass.Reportf(pos, "log message should not contain special characters or emoji")
	}

	if !cfg.DisableSensitiveCheck {
		if len(cfg.CustomSensitiveKeywords) > 0 {
			if CheckSensitiveDataWithCustomKeywords(msg, cfg.CustomSensitiveKeywords) {
				pass.Reportf(pos, "log message may contain sensitive data")
			}
		} else {
			if CheckSensitiveData(msg) {
				pass.Reportf(pos, "log message may contain sensitive data")
			}
		}
	}
}

// cleanSpecialChars removes special characters and emoji from a string.
func cleanSpecialChars(s string) string {
	var b strings.Builder
	for _, r := range s {
		if isEmoji(r) {
			continue
		}
		if strings.ContainsRune(specialChars, r) {
			continue
		}
		if !unicode.IsPrint(r) && r != ' ' {
			continue
		}
		b.WriteRune(r)
	}
	result := b.String()
	// Clean up repeated dots
	for strings.Contains(result, "...") {
		result = strings.ReplaceAll(result, "...", ".")
	}
	return strings.TrimSpace(result)
}
