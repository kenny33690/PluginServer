package logger

import "log"

func Infof(format string, args ...any) {
	log.Printf(format, args...)
}

func Fatalf(format string, args ...any) {
	log.Fatalf(format, args...)
}
