package cmd

import (
	_ "embed"
	"testing"

	_ "github.com/breml/rootcerts"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"github.com/xenos76/https-wrench/internal/requests"
)

var emptyString = ""

func TestNewHTTPSWrenchConfig(t *testing.T) {
	t.Run("new HTTPSWrenchConfig", func(t *testing.T) {
		var mc requests.RequestsMetaConfig

		config := NewHTTPSWrenchConfig()

		require.False(t, config.Debug)
		require.False(t, config.Verbose)
		require.Equal(t, config.CaBundle, emptyString)

		if diff := cmp.Diff(mc, config.RequestsMetaConfig); diff != "" {
			t.Errorf(
				"NewHTTPSWrenchConfig: RequestsMetaConfig mismatch (-want +got):\n%s",
				diff,
			)
		}
	})
}
