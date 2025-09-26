package cli

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"svc-encryption/internal/server"
)

var (
	serveListenAddr      string
	serveECPublicPath    string
	serveECPrivatePath   string
	serveSignPrivatePath string
	serveSignPublicPath  string
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the HTTP encryption service",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := server.Config{
			ListenAddr:        serveListenAddr,
			ECPublicPath:      serveECPublicPath,
			ECPrivatePath:     serveECPrivatePath,
			SigningPrivateKey: serveSignPrivatePath,
			SigningPublicKey:  serveSignPublicPath,
		}

		srv, err := server.New(cfg)
		if err != nil {
			return err
		}

		go func() {
			log.Printf("listening on %s", cfg.ListenAddr)
			if err := srv.Start(); err != nil {
				log.Fatalf("server error: %v", err)
			}
		}()

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("shutting down...")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(ctx)
	},
}

func init() {
	serveCmd.Flags().StringVar(&serveListenAddr, "listen", ":8080", "address to listen on")
	serveCmd.Flags().StringVar(&serveECPublicPath, "ec-public", "", "path to recipient EC public key (PEM)")
	serveCmd.Flags().StringVar(&serveECPrivatePath, "ec-private", "", "path to recipient EC private key (PEM)")
	serveCmd.Flags().StringVar(&serveSignPrivatePath, "signing-private", "", "path to Ed25519 signing private key (PEM)")
	serveCmd.Flags().StringVar(&serveSignPublicPath, "signing-public", "", "path to Ed25519 signing public key (PEM)")

	serveCmd.MarkFlagRequired("ec-public")
	serveCmd.MarkFlagRequired("ec-private")
}
