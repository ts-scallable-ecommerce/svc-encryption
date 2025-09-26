package cli

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"svc-encryption/internal/joseutil"
)

var (
	genOutDir       string
	genECPriv       string
	genECPub        string
	genEdPriv       string
	genEdPub        string
	genIncludeEdDSA bool
)

var genKeysCmd = &cobra.Command{
	Use:   "gen-keys",
	Short: "Generate EC (and optionally Ed25519) key material",
	RunE: func(cmd *cobra.Command, args []string) error {
		if genOutDir != "" {
			if genECPriv == "" {
				genECPriv = filepath.Join(genOutDir, "ec_private.pem")
			}
			if genECPub == "" {
				genECPub = filepath.Join(genOutDir, "ec_public.pem")
			}
			if genEdPriv == "" {
				genEdPriv = filepath.Join(genOutDir, "signing_private.pem")
			}
			if genEdPub == "" {
				genEdPub = filepath.Join(genOutDir, "signing_public.pem")
			}
		}

		if genECPriv == "" || genECPub == "" {
			return fmt.Errorf("output paths for EC keys must be provided")
		}

		if err := joseutil.GenerateECKeyPair(genECPriv, genECPub); err != nil {
			return err
		}
		cmd.Printf("generated EC key pair:\n  private: %s\n  public:  %s\n", genECPriv, genECPub)

		if genIncludeEdDSA {
			if genEdPriv == "" || genEdPub == "" {
				return fmt.Errorf("output paths for Ed25519 keys must be provided")
			}
			if err := joseutil.GenerateEd25519KeyPair(genEdPriv, genEdPub); err != nil {
				return err
			}
			cmd.Printf("generated Ed25519 key pair:\n  private: %s\n  public:  %s\n", genEdPriv, genEdPub)
		}
		return nil
	},
}

func init() {
	genKeysCmd.Flags().StringVar(&genOutDir, "out-dir", "", "directory to place generated keys")
	genKeysCmd.Flags().StringVar(&genECPriv, "ec-private", "", "path to write EC private key")
	genKeysCmd.Flags().StringVar(&genECPub, "ec-public", "", "path to write EC public key")
	genKeysCmd.Flags().StringVar(&genEdPriv, "signing-private", "", "path to write Ed25519 private key")
	genKeysCmd.Flags().StringVar(&genEdPub, "signing-public", "", "path to write Ed25519 public key")
	genKeysCmd.Flags().BoolVar(&genIncludeEdDSA, "with-signing", false, "also generate Ed25519 keys for signing")
}
