/*
 * Written by Vy Nguyen (2018)
 * Refactor from geth sources.
 */
package config

import (
	"fmt"
	"io"
	"os"
	"os/user"
	"path"
	"strings"
)

//
// @arg p - path to be expanded, can contain ~ and/or environment variables.
// @return expanded path.
//
func ExpandPath(p string) string {
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, "~\\") {
		if home := HomeDir(); home != "" {
			p = home + p[1:]
		}
	}
	return path.Clean(os.ExpandEnv(p))
}

//
// @return current user home directory.
//
func HomeDir() string {
	if home := os.Getenv("HOME"); home != "" {
		return home
	}
	if usr, err := user.Current(); err == nil {
		return usr.HomeDir
	}
	return ""
}

//
// Prefix an option name with - or -- switch.
// @return string with added prefix.
//
func PrefixedNames(fullName string) (prefixed string) {
	parts := strings.Split(fullName, ",")
	for i, name := range parts {
		name = strings.Trim(name, " ")

		prefix := "--"
		if len(name) == 1 {
			prefix = "-"
		}
		prefixed += prefix + name
		if i < (len(parts) - 1) {
			prefixed += ", "
		}
	}
	return
}

//
// Iterate and apply the function to comma separated list of names.
//
func EachName(longName string, fn func(string)) {
	parts := strings.Split(longName, ", ")
	for _, name := range parts {
		name = strings.Trim(name, " ")
		fn(name)
	}
}

func Fatal(format string, args ...interface{}) {
	w := io.MultiWriter(os.Stdout, os.Stderr)
	outf, _ := os.Stdout.Stat()
	errf, _ := os.Stderr.Stat()
	if outf != nil && errf != nil && os.SameFile(outf, errf) {
		w = os.Stderr
	}
	if args != nil {
		fmt.Fprintf(w, "Fatal: "+format+"\n", args)
	} else {
		fmt.Fprintf(w, "Fatal: "+format+"\n")
	}
	os.Exit(1)
}

func SplitAndTrim(input string) []string {
	result := strings.Split(input, ",")
	for i, r := range result {
		result[i] = strings.TrimSpace(r)
	}
	return result
}
