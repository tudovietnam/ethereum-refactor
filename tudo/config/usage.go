/*
 * Written by Vy Nguyen (2018)
 * Refactor from geth source.
 */
package config

import (
	"io"
	"sort"

	"gopkg.in/urfave/cli.v1"
)

// AppHelpTemplate is the test template for the default, global app help topic.
var (
	AppHelpTemplate = `NAME:
	{{.App.Name}} - {{.App.Usage}}

	Copyright 2018 by Vy Nguyen

USAGE:
	{{.App.HelpName}} [options]{{if .App.Commands}} command [command options]{{end}} {{if .App.ArgsUsage}}{{.App.ArgsUsage}}{{else}}[arguments...]{{end}} 

{{if .App.Version}}
VERSION:
	{{.App.Version}}
{{end}}
{{if .App.Commands}}
COMMANDS:
	{{range .App.Commands}}{{join .Names ", "}}{{ "\t" }}{{.Usage}}
	{{end}}
{{end}}
{{if .FlagGroups}}
{{range .FlagGroups}}{{.Name}} OPTIONS:
	{{range .Flags}}{{.}}
	{{end}}
{{end}}{{end}}
{{if .App.Copyright }}
COPYRIGHT:
	{{.App.Copyright}}
{{end}}
`
	CommandHelpTemplate = `{{.cmd.Name}}{{if .cmd.Subcommands}} command{{end}}{{if .cmd.Flags}} [command options]{{end}} [arguments...]

{{if .cmd.Description}}{{.cmd.Description}}{{end}}
{{if .cmd.Subcommands}}
SUBCOMMANDS:
	{{range .cmd.Subcommands}}{{.Name}}{{with .ShortName}}, {{.}}{{end}}{{ "\t" }}{{.Usage}}
	{{end}}{{end}}
{{if .categorizedFlags}}
{{range $idx, $categorized := .categorizedFlags}}{{$categorized.Name}} OPTIONS:
{{range $categorized.Flags}}{{"\t"}}{{.}}
{{end}}
{{end}}{{end}}`
)

type FlagGroup struct {
	Name  string
	Flags []cli.Flag
}

type FlagCategory []FlagGroup

type sortFlagCategory struct {
	orderCat FlagCategory
	unOrder  FlagCategory
}

func (cat sortFlagCategory) Len() int {
	return len(cat.unOrder)
}

func (cat sortFlagCategory) Swap(i, j int) {
	templ := cat.unOrder
	templ[i], templ[j] = templ[j], templ[i]
}

func (cat sortFlagCategory) Less(i, j int) bool {
	templ := cat.unOrder
	tlen := cat.Len()
	iCat, jCat := templ[i].Name, templ[j].Name
	iIdx, jIdx := tlen, tlen

	for i, group := range cat.orderCat {
		if iCat == group.Name {
			iIdx = i
		}
		if jCat == group.Name {
			jIdx = i
		}
	}
	return iIdx < jIdx
}

// GetCategory returns the category where the cli flag can be used.
//
func (templ FlagCategory) GetCategory(flag cli.Flag) string {
	for _, cat := range templ {
		for _, flg := range cat.Flags {
			if flg.GetName() == flag.GetName() {
				return cat.Name
			}
		}
	}
	return "MISC"
}

// Init sorts flags into matching category in the template.
//
func (templ FlagCategory) Init() {
	cli.AppHelpTemplate = AppHelpTemplate
	cli.CommandHelpTemplate = CommandHelpTemplate

	savedHelp := cli.HelpPrinter
	cli.HelpPrinter = func(w io.Writer, template string, data interface{}) {
		if template == AppHelpTemplate {
			categorized := make(map[string]struct{})
			for _, group := range templ {
				for _, flag := range group.Flags {
					categorized[flag.String()] = struct{}{}
				}
			}
			uncategorized := []cli.Flag{}
			for _, flag := range data.(*cli.App).Flags {
				if _, ok := categorized[flag.String()]; !ok {
					uncategorized = append(uncategorized, flag)
				}
			}
			if len(templ) > 0 && len(uncategorized) > 0 {
				tlen := len(templ) - 1
				last := len(templ[tlen].Flags)
				templ[tlen].Flags = append(templ[tlen].Flags, uncategorized...)

				defer func() {
					templ[tlen].Flags = templ[tlen].Flags[:last]
				}()
			}
			type helpData struct {
				App        interface{}
				FlagGroups FlagCategory
			}
			savedHelp(w, template, helpData{data, templ})

		} else if template == CommandHelpTemplate {
			categorized := make(map[string][]cli.Flag)
			for _, flag := range data.(cli.Command).Flags {
				if _, ok := categorized[flag.String()]; !ok {
					cat := templ.GetCategory(flag)
					categorized[cat] = append(categorized[cat], flag)
				}
			}
			sorted := make(FlagCategory, 0, len(categorized))
			for cat, flgs := range categorized {
				sorted = append(sorted, FlagGroup{cat, flgs})
			}
			sort.Sort(sortFlagCategory{
				orderCat: templ,
				unOrder:  sorted,
			})
			savedHelp(w, template, map[string]interface{}{
				"cmd":              data,
				"categorizedFlags": sorted,
			})
		} else {
			savedHelp(w, template, data)
		}
	}
}
