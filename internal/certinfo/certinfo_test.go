package certinfo

import (
	"fmt"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/stretchr/testify/require"
)

func TestNewCertinfoConfig(t *testing.T) {
	t.Run("NewCertinfoConfig", func(t *testing.T) {
		t.Parallel()

		cc, err := NewCertinfoConfig()
		require.NoError(t, err)

		require.NotNil(t, cc.CACertsPool)
	})
}

type mockReader struct {
	readError error
}

func (mr mockReader) ReadFile(name string) ([]byte, error) {
	mr.readError = fmt.Errorf("unable to read file %s", name)
	return nil, mr.readError
}

func TestCertinfo_SetCaPoolFromFile(t *testing.T) {
	t.Run("FileReadErrors", func(t *testing.T) {
		t.Parallel()

		cc, err := NewCertinfoConfig()
		require.NoError(t, err)

		errEmpty := cc.SetCaPoolFromFile(emptyString, inputReader)
		require.NoError(t, errEmpty, "error emptyString")

		errNoRead := cc.SetCaPoolFromFile(unreadableFile, mockErrReader)
		require.Error(t, errNoRead, "error unreadableFile")
		assert.Equal(t,
			"failed to read CA bundle file: unable to read file testdata/unreadable-file.txt",
			errNoRead.Error(),
			"check unreadableFile",
		)

		errNoExist := cc.SetCaPoolFromFile("testdata/not-exist", inputReader)
		require.Error(t, errNoExist, "error file not-exist")
		assert.Equal(t,
			"failed to read CA bundle file: open testdata/not-exist: no such file or directory",
			errNoExist.Error(),
			"read not-exist file",
		)

		errWrongCert := cc.SetCaPoolFromFile(RSACaCertKeyFile, inputReader)
		require.Error(t, errWrongCert, "error wrong cert")
		assert.Equal(t,
			"unable to create CertPool from file",
			errWrongCert.Error(),
			"check wrong cert",
		)

		// TODO: complete, compare struct data with input
		errRSACACert := cc.SetCaPoolFromFile(RSACaCertFile, inputReader)
		require.NoError(t, errRSACACert, "error generated RSACaCertFile")
	})
}
