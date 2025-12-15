package certinfo

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
)

type mockReader struct {
	readError error
}

func (mr mockReader) ReadFile(name string) ([]byte, error) {
	mr.readError = fmt.Errorf("unable to read file %s", name)
	return nil, mr.readError
}

func TestNewCertinfoConfig(t *testing.T) {
	t.Run("NewCertinfoConfig", func(t *testing.T) {
		t.Parallel()

		cc, err := NewCertinfoConfig()
		require.NoError(t, err)

		require.NotNil(t, cc.CACertsPool)
	})
}

var certinfoConfigFileReadErrorTests = []struct {
	desc        string
	caCertFile  string
	certFile    string
	keyFile     string
	reader      Reader
	expectError bool
	expectMsg   map[string]string
}{
	{
		desc:        "emptyString",
		caCertFile:  emptyString,
		certFile:    emptyString,
		keyFile:     emptyString,
		reader:      inputReader,
		expectError: false,
	},
	{
		desc:        "unreadableFile",
		caCertFile:  unreadableFile,
		certFile:    unreadableFile,
		keyFile:     unreadableFile,
		reader:      mockErrReader,
		expectError: true,
		expectMsg: map[string]string{
			"caPool": "failed to read CA bundle file: unable to read file testdata/unreadable-file.txt",
			"certs":  "error reading certificate file: unable to read file testdata/unreadable-file.txt",
			"key":    "unable to read file testdata/unreadable-file.txt",
		},
	},
	{
		desc:        "not exist",
		caCertFile:  "testdata/not-exist",
		certFile:    "testdata/not-exist",
		keyFile:     "testdata/not-exist",
		reader:      inputReader,
		expectError: true,
		expectMsg: map[string]string{
			"caPool": "failed to read CA bundle file: open testdata/not-exist: no such file or directory",
			"certs":  "error reading certificate file: open testdata/not-exist: no such file or directory",
			"key":    "open testdata/not-exist: no such file or directory",
		},
	},
	{
		desc:        "wrong file",
		caCertFile:  sampleTextFile,
		certFile:    sampleTextFile,
		keyFile:     sampleTextFile,
		reader:      inputReader,
		expectError: true,
		expectMsg: map[string]string{
			"caPool": "unable to create CertPool from file",
			"certs":  "no valid certificates found in file testdata/sample-text.txt",
			"key":    "failed to decode PEM",
		},
	},
	{
		desc: "wrong PEM encoded file",

		// PEM encoded keys get discarded by (_ *CertPool) AppendCertsFromPEM()
		// but do not trigger errors (ok == false)
		caCertFile:  RSASamplePKCS8PlaintextPrivateKey,
		certFile:    ECDSASamplePlaintextPrivateKey,
		keyFile:     ED25519SampleCertificate,
		reader:      inputReader,
		expectError: true,
		expectMsg: map[string]string{
			"caPool": "unable to create CertPool from file",
			"certs":  "no valid certificates found in file testdata/ecdsa-plaintext-private-key.pem",
			"key":    "unsupported key format or invalid password",
		},
	},
}

func TestCertinfo_SetCaPoolFromFile(t *testing.T) {
	for _, tc := range certinfoConfigFileReadErrorTests {
		tt := tc
		t.Run("File Read Error Test "+tt.desc, func(t *testing.T) {
			t.Parallel()

			cc, errNew := NewCertinfoConfig()
			require.NoError(t, errNew)

			err := cc.SetCaPoolFromFile(tt.caCertFile, tt.reader)

			// CertinfoConfig methods do nothing if an empty string is passed
			// as filePath
			if tt.caCertFile == emptyString {
				require.NoError(t, err)
				return
			}

			require.Error(t, err)
			require.EqualError(
				t,
				err,
				tt.expectMsg["caPool"],
			)
		})
	}

	t.Run("File Read Success Test", func(t *testing.T) {
		t.Parallel()

		cc, errNew := NewCertinfoConfig()
		require.NoError(t, errNew)

		err := cc.SetCaPoolFromFile(
			RSACaCertFile,
			inputReader,
		)

		require.NoError(t, err)

		require.Equal(t, RSACaCertFile, cc.CACertsFilePath)

		wantPool, errWantPool := GetRootCertsFromFile(
			RSACaCertFile,
			inputReader,
		)
		require.NoError(t, errWantPool)

		require.True(t, wantPool.Equal(cc.CACertsPool))

		if diff := cmp.Diff(wantPool, cc.CACertsPool); diff != "" {
			t.Errorf(
				"SetCaPoolFromFile: pool mismatch (-want +got):\n%s",
				diff,
			)
		}
	})
}

func TestCertinfo_SetCertsFromFile(t *testing.T) {
	for _, tc := range certinfoConfigFileReadErrorTests {
		tt := tc
		t.Run("File Read Error Test "+tt.desc, func(t *testing.T) {
			t.Parallel()

			cc, errNew := NewCertinfoConfig()
			require.NoError(t, errNew)

			err := cc.SetCertsFromFile(tt.certFile, tt.reader)

			// CertinfoConfig methods do nothing if an empty string is passed
			// as filePath
			if tt.certFile == emptyString {
				require.NoError(t, err)
				return
			}

			require.Error(t, err)
			require.EqualError(
				t,
				err,
				tt.expectMsg["certs"],
			)
		})
	}

	t.Run("File Read Success Test", func(t *testing.T) {
		t.Parallel()

		cc, errNew := NewCertinfoConfig()
		require.NoError(t, errNew)

		err := cc.SetCertsFromFile(
			RSASamplePKCS8Certificate,
			inputReader,
		)

		require.NoError(t, err)

		require.Equal(t, RSASamplePKCS8Certificate, cc.CertsBundleFilePath)

		wantCerts, errWantCrt := GetCertsFromBundle(
			RSASamplePKCS8Certificate,
			inputReader,
		)
		require.NoError(t, errWantCrt)

		if diff := cmp.Diff(wantCerts, cc.CertsBundle); diff != "" {
			t.Errorf(
				"SetCertsFromFile: pool mismatch (-want +got):\n%s",
				diff,
			)
		}
	})
}

func TestCertinfo_SetPrivateKeyFromFile(t *testing.T) {
	for _, tc := range certinfoConfigFileReadErrorTests {
		tt := tc
		t.Run("File Read Error Test "+tt.desc, func(t *testing.T) {
			t.Parallel()

			cc, errNew := NewCertinfoConfig()
			require.NoError(t, errNew)

			err := cc.SetPrivateKeyFromFile(
				tt.keyFile,
				privateKeyPwEnvVar,
				tt.reader,
			)

			// CertinfoConfig methods do nothing if an empty string is passed
			// as filePath
			if tt.keyFile == emptyString {
				require.NoError(t, err)
				return
			}

			require.Error(t, err)
			require.EqualError(
				t,
				err,
				tt.expectMsg["key"],
			)
		})
	}

	t.Run("File Read Success Test", func(t *testing.T) {
		t.Parallel()

		cc, errNew := NewCertinfoConfig()
		require.NoError(t, errNew)

		err := cc.SetPrivateKeyFromFile(
			ED25519SamplePlaintextPrivateKey,
			privateKeyPwEnvVar,
			inputReader,
		)

		require.NoError(t, err)

		require.Equal(t, ED25519SamplePlaintextPrivateKey, cc.PrivKeyFilePath)

		wantKey, errKey := GetKeyFromFile(
			ED25519SamplePlaintextPrivateKey,
			privateKeyPwEnvVar,
			inputReader,
		)
		require.NoError(t, errKey)

		if diff := cmp.Diff(wantKey, cc.PrivKey); diff != "" {
			t.Errorf(
				"SetCertsFromFile: pool mismatch (-want +got):\n%s",
				diff,
			)
		}
	})
}

func TestCertinfo_SetTLSInsecure(t *testing.T) {
	tests := []bool{
		true,
		false,
	}

	for _, tc := range tests {
		tt := tc
		testname := fmt.Sprintf("%v", tt)
		t.Run(testname, func(t *testing.T) {
			t.Parallel()

			cc, errNew := NewCertinfoConfig()
			require.NoError(t, errNew)

			cc.SetTLSInsecure(tt)

			require.Equal(
				t,
				tt,
				cc.TLSInsecure,
			)
		})
	}
}

func TestCertinfo_SetTLSServeName(t *testing.T) {
	tests := []string{
		emptyString,
		"test",
		"example.com",
	}

	for _, tc := range tests {
		tt := tc
		testname := fmt.Sprintf("%v", tt)
		t.Run(testname, func(t *testing.T) {
			t.Parallel()

			cc, errNew := NewCertinfoConfig()
			require.NoError(t, errNew)

			cc.SetTLSServerName(tt)

			require.Equal(
				t,
				tt,
				cc.TLSServerName,
			)
		})
	}
}
