package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "svc-encryption",
	Short: "A JOSE-based encryption service and toolkit",
	Long:  `svc-encryption provides HTTP APIs and CLI utilities for encrypting and decrypting payloads using JWE (ECDH-ES + A256GCM) with optional EdDSA signatures.`,
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(encryptCmd)
	rootCmd.AddCommand(decryptCmd)
	rootCmd.AddCommand(genKeysCmd)
}
