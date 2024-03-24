package utils

import (
	"encoding/json"
	"os"
)

type FilterObject struct {
	Key   KeyObject   `json:"key"`
	Value ValueObject `json:"value"`
}

type KeyObject struct {
	Eq       string `json:"eq"`
	IfAbsent string `json:"ifAbsent"`
}

type ValueObject struct {
	Regex string `json:"regex"`
}

func GetFilter() []FilterObject {
	// Example JSON data
	/*
		[{
			"key": {
				"eq": "x-envoy-peer-metadata-id",
				"ifAbsent": "reject" // accept
			},
			"value": {
				"regex": ".*bookinfo.*"
			}
		}]
	*/
	data := os.Getenv("AKTO_MODULE_DISCOVERY_CONFIG")

	/* this default filter is configured to trace only
	the traffic between envoy proxies and the application containers.
	*/
	defaultFilter := []FilterObject{
		{
			Key: KeyObject{
				Eq:       "x-envoy-peer-metadata-id",
				IfAbsent: "accept",
			},
			Value: ValueObject{
				Regex: ".*sidecar.*",
			},
		},
	}

	if len(data) == 0 {
		return defaultFilter
	}

	var filters []FilterObject

	err := json.Unmarshal([]byte(data), &filters)
	if err != nil {
		return defaultFilter
	}

	return filters
}
