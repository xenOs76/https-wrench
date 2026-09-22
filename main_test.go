package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRun verifies that Run and main execute without unexpected panics.
func TestRun(t *testing.T) {
	t.Run("Run", func(t *testing.T) {
		err := Run()
		require.NoError(t, err)
	})

	t.Run("Main", func(_ *testing.T) {
		main()
	})
}
