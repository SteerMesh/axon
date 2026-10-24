//go:build windows

package main

import "fmt"

func attach(string, string, uint64) error {
	return fmt.Errorf("interactive attach is not supported on Windows yet")
}
