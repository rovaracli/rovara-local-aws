package main

import (
	"os"
	"os/signal"
	"syscall"
)

func notifyTerm(c chan os.Signal) { signal.Notify(c, syscall.SIGTERM, syscall.SIGINT) }
