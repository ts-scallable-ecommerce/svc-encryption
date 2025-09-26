package cli

import (
	"errors"

	"github.com/spf13/cobra"

	"svc-encryption/internal/joseutil"
)

var (
	decryptInputPath     string
	decryptOutputPath    string
	decryptPrivatePath   string
	decryptVerifyKeyPath string
	decryptVerify        bool
)

var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt a compact JWE",
	RunE: func(cmd *cobra.Command, args []string) error {
		if decryptPrivatePath == "" {
			return errors.New("EC private key path is required")
		}
		priv, err := joseutil.LoadECPrivateKey(decryptPrivatePath)
		if err != nil {
			return err
		}
		verifyKey, err := joseutil.LoadEd25519PublicKey(decryptVerifyKeyPath)
		if err != nil {
			return err
		}
		if decryptVerify && len(verifyKey) == 0 {
			return errors.New("verify flag set but Ed25519 public key missing")
		}
		tokenBytes, err := readInput(decryptInputPath)
		if err != nil {
			return err
		}
		payload, verified, err := joseutil.Decrypt(string(bytesTrimSpace(tokenBytes)), priv, verifyKey, decryptVerify)
		if err != nil {
			return err
		}
		if err := writeOutput(payload, decryptOutputPath); err != nil {
			return err
		}
		if decryptVerify {
			cmd.Printf("signature verified: %v\n", verified)
		}
		return nil
	},
}

func init() {
	decryptCmd.Flags().StringVarP(&decryptInputPath, "input", "i", "", "path to input JWE file (defaults to stdin)")
	decryptCmd.Flags().StringVarP(&decryptOutputPath, "output", "o", "", "path to output file (defaults to stdout)")
	decryptCmd.Flags().StringVar(&decryptPrivatePath, "ec-private", "", "path to EC private key (PEM)")
	decryptCmd.Flags().StringVar(&decryptVerifyKeyPath, "signing-public", "", "path to Ed25519 public key (PEM)")
	decryptCmd.Flags().BoolVar(&decryptVerify, "verify", false, "verify EdDSA signature inside the payload")
}

func bytesTrimSpace(in []byte) []byte {
	start := 0
	for start < len(in) && (in[start] == '\n' || in[start] == '\r' || in[start] == '\t' || in[start] == ' ') {
		start++
	}
	end := len(in)
	for end > start && (in[end-1] == '\n' || in[end-1] == '\r' || in[end-1] == '\t' || in[end-1] == ' ') {
		end--
	}
	return in[start:end]
}
