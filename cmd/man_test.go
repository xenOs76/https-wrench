package cmd

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMan(t *testing.T) {
	t.Run("Run manCmd", func(t *testing.T) {
		destDir := t.TempDir()
		manBuf := new(bytes.Buffer)
		rootCmd.SetOut(manBuf)
		rootCmd.SetErr(manBuf)
		rootCmd.SetArgs([]string{"man", "--dest-dir", destDir})

		err := rootCmd.Execute()
		require.NoError(t, err)

		rootCmd.SetArgs([]string{"man", "--dest-dir", "fake-dir"})
		errWrongDir := rootCmd.Execute()
		require.NoError(t, errWrongDir)
		require.FileExists(t, filepath.Join(destDir, "https-wrench.1"))
		// WARN stdout does not get into the buffer
		// require.Contains(t, manBuf.String(), "no such file or directory--- FAIL")
	})
}
