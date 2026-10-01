//go:build !windows

package main

func platformMain(appMain func()) {
	appMain()
}

func collectorIdFilePath() string {
	return "/collector_id_file"
}
