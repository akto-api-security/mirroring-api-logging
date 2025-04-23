package utils

import (
	"math"
	"time"
)

func EpochMinutes() (int, int) {
	now := time.Now().Unix()
	minutes := float64(now) / 60.0
	roundedUp := math.Ceil(minutes)
	roundedDown := math.Floor(minutes)
	return int(roundedDown), int(roundedUp)
}

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
