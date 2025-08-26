package application

import "time"

// Clock interface supaya gampang ditest
type Clock interface {
	Now() time.Time
}

// SystemClock implementasi default, pakai time.Now()
type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now() }
