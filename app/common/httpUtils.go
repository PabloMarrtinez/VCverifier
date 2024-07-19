package common

import "strings"

func BuildUrlString(address string, path string) string {
	if strings.HasSuffix(address, "/") {
		if strings.HasPrefix(path, "/") {
			return address + strings.TrimPrefix(path, "/")
		} else {
			return address + path
		}
	} else {
		if strings.HasPrefix(path, "/") {
			return address + path
		} else {
			return address + "/" + path
		}
	}
}
