package elf

import "debug/dwarf"

type ClassInfo struct {
	name         string
	inheritances []*ClassInheritance
	members      []*dwarf.StructField
}

func (c *ClassInfo) GetInheritanceOffset(name string) int64 {
	for _, i := range c.inheritances {
		if i.name == name {
			return int64(i.offset)
		}
	}
	return -1
}

func (c *ClassInfo) GetMemberOffset(name string) int64 {
	for _, m := range c.members {
		if m.Name == name {
			return m.ByteOffset
		}
	}
	return -1
}

type ClassInheritance struct {
	name   string
	cType  *dwarf.StructType
	offset uint64
}
