package config

import (
	"flag"
	"fmt"
)

type DirectoryString struct {
	Value string
}

func (self *DirectoryString) String() string {
	return self.Value
}

func (self *DirectoryString) Set(value string) error {
	self.Value = ExpandPath(value)
	return nil
}

// Custom cli.Flag type which expand the received string to an absolute path.
// e.g. ~/.ethereum -> /home/username/.ethereum
//
type DirectoryFlag struct {
	Name  string
	Value DirectoryString
	Usage string
}

func (self DirectoryFlag) String() string {
	fmtString := "%s %v\t%v"
	value := self.Value.String()
	if len(value) > 0 {
		fmtString = "%s \"%v\"\t%v"
	}
	return fmt.Sprintf(fmtString, PrefixedNames(self.Name), value, self.Usage)
}

func (self DirectoryFlag) Apply(set *flag.FlagSet) {
	EachName(self.Name, func(name string) {
		set.Var(&self.Value, self.Name, self.Usage)
	})
}

func (self DirectoryFlag) GetName() string {
	return self.Name
}

func (self *DirectoryFlag) Set(value string) {
	self.Value.Value = value
}
