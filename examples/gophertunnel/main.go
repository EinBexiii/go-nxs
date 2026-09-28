// Command gophertunnel runs a minimal gophertunnel server that players join through an
// NXS provider.
package main

import (
	"context"
	"flag"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"strings"

	"github.com/df-mc/go-nxs"
	"github.com/sandertv/gophertunnel/minecraft"
)

func main() {
	var (
		origin    = flag.String("origin", os.Getenv("NXS_ORIGIN"), "HTTPS origin of the provider")
		token     = flag.String("token", os.Getenv("NXS_TOKEN"), "bearer token used to register, if any")
		stateDir  = flag.String("state", "nxs-state", "directory holding the state of this instance")
		addr      = flag.String("addr", ":19133", "UDP address players connect to")
		endpoints = flag.String("endpoints", "", "comma-separated public UDP endpoints to advertise, such as 203.0.113.1:19133")
		assisted  = flag.Bool("assisted", false, "enable assisted joins over the WebSocket control transport")
		diag      = flag.Bool("diagnostics", false, "enable connectivity diagnostics")
		debug     = flag.Bool("debug", false, "enable debug logging")
		dereg     = flag.Bool("deregister", false, "deregister the saved instance and exit")
	)
	flag.Parse()

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	conf := nxs.Config{Origin: *origin, Token: *token, StateDir: *stateDir, Address: *addr, WebSocket: true,
		AssistedJoins: *assisted, Diagnostics: *diag, GameOutcomes: true, Log: log}
	for _, e := range strings.Split(*endpoints, ",") {
		if e = strings.TrimSpace(e); e != "" {
			ap, err := netip.ParseAddrPort(e)
			if err != nil {
				log.Error("invalid endpoint", "endpoint", e, "error", err)
				os.Exit(1)
			}
			conf.Endpoints = append(conf.Endpoints, ap)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	provider, err := nxs.New(ctx, conf)
	if err != nil {
		log.Error("start provider", "error", err)
		os.Exit(1)
	}
	defer provider.Close()
	if *dereg {
		if err := provider.Deregister(ctx); err != nil {
			log.Error("deregister", "error", err)
			os.Exit(1)
		}
		log.Info("deregistered")
		return
	}
	log.Info("listening", "addr", provider.Addr(), "publicAddress", provider.PublicAddress())

	l, err := minecraft.ListenConfig{
		StatusProvider: minecraft.NewStatusProvider("NXS Example", "gophertunnel"),
	}.ListenNetwork(minecraft.NetherNet{Signaling: provider, Log: log}, "")
	if err != nil {
		log.Error("listen", "error", err)
		os.Exit(1)
	}
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()

	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		provider.GameJoined(c)
		go handle(c.(*minecraft.Conn), log)
	}
}

func handle(conn *minecraft.Conn, log *slog.Logger) {
	defer conn.Close()
	log.Info("player joined", "name", conn.IdentityData().DisplayName, "addr", conn.RemoteAddr())
	if err := conn.StartGame(minecraft.GameData{}); err != nil {
		log.Warn("start game", "error", err)
		return
	}
	for {
		if _, err := conn.ReadPacket(); err != nil {
			log.Info("player left", "name", conn.IdentityData().DisplayName, "error", err)
			return
		}
	}
}
