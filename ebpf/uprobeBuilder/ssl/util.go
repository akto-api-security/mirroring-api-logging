package ssl

import (
	"strings"
)

func FindModules(modules map[string]bool, names ...string) (map[string]string, error) {
	result := make(map[string]string)
	for mod := range modules {
		for _, modName := range names {
			if strings.Contains(mod, modName) {
				result[modName] = mod
			}
		}
	}
	return result, nil
}
