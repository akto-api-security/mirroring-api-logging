package version

import (
	"fmt"
	"strconv"
)

type Version struct {
	Major int
	Minor int
	Patch int
}

func Build(major, minor, patch int) *Version {
	return &Version{Major: major, Minor: minor, Patch: patch}
}

func Read(majorVal, minorVal, patchVal string) (*Version, error) {
	result := &Version{}
	var err error
	result.Major, err = parseVal(err, "major", majorVal)
	result.Minor, err = parseVal(err, "minor", minorVal)
	result.Patch, err = parseVal(err, "patch", patchVal)
	return result, err
}

func (v *Version) GreaterOrEquals(o *Version) bool {
	var compare int
	compare = v.compare(compare, v.Major, o.Major)
	compare = v.compare(compare, v.Minor, o.Minor)
	compare = v.compare(compare, v.Patch, o.Patch)
	return compare >= 0
}

func (v *Version) compare(res, before, after int) int {
	if res != 0 {
		return res
	}
	if before > after {
		return 1
	} else if before == after {
		return 0
	}
	return -1
}

func (v *Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

func parseVal(err error, name, val string) (int, error) {
	if err != nil {
		return 0, err
	}
	if val == "" {
		return 0, nil
	}
	atoi, err := strconv.Atoi(val)
	if err != nil {
		return 0, fmt.Errorf("the %s version is a number, version: %s", name, val)
	}
	return atoi, nil
}
