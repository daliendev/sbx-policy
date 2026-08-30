package ui

import (
	"fmt"
	"os"
)

func Success(format string, args ...interface{}) {
	fmt.Printf("✓ "+format+"\n", args...)
}

func Info(format string, args ...interface{}) {
	fmt.Printf(format+"\n", args...)
}

func Warning(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "⚠ "+format+"\n", args...)
}

func Error(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "✗ "+format+"\n", args...)
}

func PrintList(items []string, bullet string) {
	for _, item := range items {
		fmt.Printf("  %s %s\n", bullet, item)
	}
}

func PrintDiff(added, removed []string) {
	for _, e := range added {
		fmt.Printf("  + %s\n", e)
	}
	for _, e := range removed {
		fmt.Printf("  - %s\n", e)
	}
}

func Separator() {
	fmt.Println()
}

func IsTerminal() bool {
	return os.Getenv("TERM") != "dumb" && os.Getenv("NO_COLOR") == ""
}

func Dim(format string, args ...interface{}) string {
	if !IsTerminal() {
		return fmt.Sprintf(format, args...)
	}
	return fmt.Sprintf("\033[2m"+format+"\033[0m", args...)
}

func Bold(format string, args ...interface{}) string {
	if !IsTerminal() {
		return fmt.Sprintf(format, args...)
	}
	return fmt.Sprintf("\033[1m"+format+"\033[0m", args...)
}
