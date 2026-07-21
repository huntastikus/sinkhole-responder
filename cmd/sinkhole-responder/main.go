package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/huntastikus/sinkhole-responder/internal/app"
	"github.com/huntastikus/sinkhole-responder/internal/config"
	"github.com/huntastikus/sinkhole-responder/internal/logbuf"
	"github.com/huntastikus/sinkhole-responder/internal/tlsx"
)

var version = "dev"

func main() {
	os.Exit(run())
}

func run() int {
	if len(os.Args) > 1 && os.Args[1] == "create-ca" {
		return runCreateCA(os.Args[2:])
	}

	configPath := flag.String("config", "config.yaml", "path to the configuration file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Fprintln(os.Stdout, version)
		return 0
	}

	if _, statErr := os.Stat(*configPath); errors.Is(statErr, os.ErrNotExist) {
		if err := config.WriteDefaultConfig(*configPath); err != nil {
			fmt.Fprintf(os.Stderr, "seed default configuration: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "seeded a default configuration at %s (edit it in the admin UI)\n", *configPath)
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load configuration: %v\n", err)
		return 1
	}

	var initialLevel slog.Level
	if err := initialLevel.UnmarshalText([]byte(cfg.Logging.Level)); err != nil {
		fmt.Fprintf(os.Stderr, "parse logging level: %v\n", err)
		return 1
	}
	var level slog.LevelVar
	level.Set(initialLevel)
	jsonHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: &level})
	logRing := logbuf.NewRing(500)
	logger := slog.New(logRing.Handler(jsonHandler))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)

	reloadCh := make(chan string, 1)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				select {
				case reloadCh <- *configPath:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	if err := app.Run(ctx, cfg, version, logger, logRing, reloadCh,
		app.WithConfigPath(*configPath),
		app.WithLogLevel(&level),
	); err != nil {
		logger.Error("sinkhole responder stopped", "error", err)
		return 1
	}
	return 0
}

func runCreateCA(args []string) int {
	flags := flag.NewFlagSet("create-ca", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	directory := flags.String("dir", "", "directory for the new CA files")
	commonName := flags.String("cn", "Sinkhole Responder Local CA", "CA common name")
	years := flags.Int("years", 5, "CA lifetime in years")
	flags.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: sinkhole-responder create-ca -dir DIR [-cn NAME] [-years N]")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return 1
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "create-ca: unexpected arguments: %v\n", flags.Args())
		flags.Usage()
		return 1
	}
	if *directory == "" {
		fmt.Fprintln(os.Stderr, "create-ca: -dir is required")
		flags.Usage()
		return 1
	}

	fmt.Fprintln(os.Stderr, `WARNING: You are creating a local certificate authority.
Once trusted by a browser or operating system, this CA lets this tool impersonate ANY HTTPS site to that client.
Use it only in an isolated lab/home environment. Never distribute it or install it system-wide. Protect the private key.`)

	certPath, keyPath, err := tlsx.CreateCA(*directory, *commonName, *years)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create CA: %v\n", err)
		return 1
	}

	fmt.Fprintf(os.Stdout, `Created local CA:
  certificate: %s
  private key: %s

Configure the responder:
tls:
  mode: local-ca
  local_ca:
    ca_cert: %s
    ca_key: %s

Keep the key chmod-protected (0600 or 0400). Trust the certificate only in a dedicated LAB browser profile; never install it system-wide.
`, certPath, keyPath, certPath, keyPath)
	return 0
}
