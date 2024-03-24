package utils

import (
	"math"
	"time"
)

func EpochHours() (int, int) {
	now := time.Now().Unix()
	hours := float64(now) / 3600.0
	roundedUp := math.Ceil(hours)
	roundedDown := math.Floor(hours)
	return int(roundedDown), int(roundedUp)
}

func EpochDays() (int, int) {
	now := time.Now().Unix()
	hours := float64(now) / 86400.0
	roundedUp := math.Ceil(hours)
	roundedDown := math.Floor(hours)
	return int(roundedDown), int(roundedUp)
}
