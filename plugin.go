package logchecklint

import (
	"github.com/golangci/plugin-module-register/register"
	"github.com/manakovpavel1997-lab/logchecklint/pkg/analyzer"
	"golang.org/x/tools/go/analysis"
)

func init() {
	register.Plugin("logchecklint", newPlugin)
}

func newPlugin(settings any) (register.LinterPlugin, error) {
	var cfg analyzer.Config

	if settings != nil {
		var err error
		cfg, err = register.DecodeSettings[analyzer.Config](settings)
		if err != nil {
			return nil, err
		}
	}

	return &plugin{cfg: cfg}, nil
}

type plugin struct {
	cfg analyzer.Config
}

var _ register.LinterPlugin = (*plugin)(nil)

func (p *plugin) BuildAnalyzers() ([]*analysis.Analyzer, error) {
	a := &analysis.Analyzer{
		Name: "logchecklint",
		Doc:  "checks log messages for common issues: uppercase start, non-English text, special characters, sensitive data",
		Run:  analyzer.RunWithConfig(p.cfg),
		Requires: analyzer.Analyzer.Requires,
	}

	return []*analysis.Analyzer{a}, nil
}

func (p *plugin) GetLoadMode() string {
	return register.LoadModeSyntax
}
