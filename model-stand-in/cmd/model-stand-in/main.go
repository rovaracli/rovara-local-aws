// model-stand-in is Rovara's fake SageMaker inference container for a sealed run. See package standin.
//
//	model-stand-in --config /rovara/model-stand-in.json    serve (the image's default)
//	model-stand-in --config file --validate                check the config and exit 0 or 1
//
// It reads one file, listens, and writes one log line per request (sizes and a short hash, never a body) to standard error. It makes no outgoing connection.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"sync"
	"syscall"

	"rovara/model-stand-in/internal/standin"
)

func main() { os.Exit(run(os.Args[1:], os.Stderr)) }

func run(args []string, logOut io.Writer) int {
	fs := flag.NewFlagSet("model-stand-in", flag.ContinueOnError)
	fs.SetOutput(logOut)
	path := fs.String("config", "/rovara/model-stand-in.json", "the config file the worker wrote")
	validate := fs.Bool("validate", false, "check the config and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	f, err := os.Open(*path)
	if err != nil {
		fmt.Fprintln(logOut, "model-stand-in: the config file cannot be opened")
		return 1
	}
	data, err := io.ReadAll(io.LimitReader(f, standin.MaxConfigBytes+1))
	f.Close()
	if err != nil {
		fmt.Fprintln(logOut, "model-stand-in: the config file cannot be read")
		return 1
	}
	cfg, err := standin.ParseConfig(data)
	if err != nil {
		fmt.Fprintln(logOut, "model-stand-in:", err)
		return 1
	}
	log := slog.New(slog.NewTextHandler(logOut, nil))
	// A soft limit below the catalog's memory (128 MiB): the collector works harder before the kernel would kill the container.
	debug.SetMemoryLimit(96 << 20)
	if *validate {
		log.Info("config ok", "endpoints", standin.Describe(cfg))
		return 0
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	srv := standin.New(cfg, log)
	listeners := srv.Listeners()
	log.Info("serving", "endpoints", standin.Describe(cfg), "listeners", len(listeners))
	var wg sync.WaitGroup
	failed := make(chan error, len(listeners))
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	for _, l := range listeners {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := standin.Serve(runCtx, l); err != nil {
				failed <- fmt.Errorf("listener %s: %w", l.Addr, err)
				cancel()
			}
		}()
	}
	wg.Wait()
	select {
	case err := <-failed:
		fmt.Fprintln(logOut, "model-stand-in:", err)
		return 1
	default:
		return 0
	}
}
