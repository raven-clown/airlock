//go:build !windows

package runtime

import (
	"os"
	"os/signal"
	"syscall"
)

func hangups() <-chan os.Signal {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	return ch
}
