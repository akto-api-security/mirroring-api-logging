package elf

import "debug/dwarf"

type FunctionInfo struct {
	name string
	args map[string]*FunctionArgsInfo
}

func (f *FunctionInfo) Name() string {
	return f.name
}

func (f *FunctionInfo) Args(name string) *FunctionArgsInfo {
	return f.args[name]
}

type FunctionArgsInfo struct {
	tp       dwarf.Type
	IsRet    bool
	Location *ArgLocation
}
