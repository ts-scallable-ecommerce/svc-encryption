package cli

import (
	"errors"

	"github.com/spf13/cobra"

	"svc-encryption/internal/joseutil"
)

var (
	encryptInputPath      string
	encryptOutputPath     string
	encryptPublicKeyPath  string
	encryptSignPrivateKey string
	encryptSign           bool
)

var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt plaintext into a compact JWE",
	RunE: func(cmd *cobra.Command, args []string) error {
		if encryptPublicKeyPath == "" {
			return errors.New("recipient public key path is required")
		}
		pub, err := joseutil.LoadECPublicKey(encryptPublicKeyPath)
		if err != nil {
			return err
		}
		privSign, err := joseutil.LoadEd25519PrivateKey(encryptSignPrivateKey)
		if err != nil {
			return err
		}
		if encryptSign && len(privSign) == 0 {
			return errors.New("sign flag set but signing private key missing")
		}

		data, err := readInput(encryptInputPath)
		if err != nil {
			return err
		}
		token, err := joseutil.Encrypt(data, pub, privSign, encryptSign)
		if err != nil {
			return err
		}
		if err := writeOutput([]byte(token), encryptOutputPath); err != nil {
			return err
		}
		return nil
	},
}

func init() {
	encryptCmd.Flags().StringVarP(&encryptInputPath, "input", "i", "", "path to input file (defaults to stdin)")
	encryptCmd.Flags().StringVarP(&encryptOutputPath, "output", "o", "", "path to output file (defaults to stdout)")
	encryptCmd.Flags().StringVar(&encryptPublicKeyPath, "ec-public", "", "path to recipient EC public key (PEM)")
	encryptCmd.Flags().StringVar(&encryptSignPrivateKey, "signing-private", "", "path to Ed25519 signing private key (PEM)")
	encryptCmd.Flags().BoolVar(&encryptSign, "sign", false, "sign plaintext with EdDSA before encrypting")
}
