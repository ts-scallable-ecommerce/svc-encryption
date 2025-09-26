package cli

import (
	"fmt"
	"io"
	"os"
)

func readInput(path string) ([]byte, error) {
	var data []byte
	var err error
	if path == "" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}
	return data, nil
}

func writeOutput(data []byte, path string) error {
	var err error
	if path == "" {
		_, err = os.Stdout.Write(data)
		if err == nil {
			_, err = os.Stdout.WriteString("\n")
		}
	} else {
		err = os.WriteFile(path, data, 0600)
	}
	if err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}
