package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRun(t *testing.T) {
	t.Run("Run", func(t *testing.T) {
		err := Run()
		require.NoError(t, err)
	})
}
