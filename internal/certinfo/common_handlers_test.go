package certinfo

import (
	"bytes"
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
)

func TestCertinfo_GetRootCertsFromFile(t *testing.T) {
	t.Run("FileReadErrors", func(t *testing.T) {
		t.Parallel()

		_, errEmptyString := GetRootCertsFromFile(
			emptyString,
			inputReader,
		)
		require.Error(t, errEmptyString)
		require.ErrorIs(t, errEmptyString, ErrEmptyArg)
		gotEmpty, ok := errors.AsType[*EmptyArgError](errEmptyString)
		require.True(t, ok)
		require.Equal(t, "caBundlePath", gotEmpty.Name)

		_, errNoRead := GetRootCertsFromFile(
			unreadableFile,
			mockErrReader,
		)
		require.Error(t, errNoRead)
		require.ErrorContains(t, errNoRead, "failed to read CA bundle file:")

		_, errWrongFile := GetRootCertsFromFile(
			RSACaCertKeyFile,
			inputReader,
		)
		require.ErrorIs(t, errWrongFile, ErrCertPoolFromFile)
	})

	t.Run("CertImportValidation", func(t *testing.T) {
		pool, errCaFile := GetRootCertsFromFile(
			RSACaCertFile,
			inputReader,
		)
		require.NoError(t, errCaFile)

		if diff := cmp.Diff(RSACaCertPool, pool); diff != "" {
			t.Errorf(
				"RSACACertPool vs imported Cert Pool mismatch (-want +got):\n%s",
				diff,
			)
		}
	})

	t.Run("nil Reader error", func(t *testing.T) {
		_, err := GetRootCertsFromFile(
			RSACaCertFile,
			nil,
		)
		require.ErrorIs(t, err, ErrNilReader)
	})
}

func TestCertinfo_GetRootCertsFromString(t *testing.T) {
	t.Run("ReadErrors", func(t *testing.T) {
		t.Parallel()

		_, errEmptyString := GetRootCertsFromString(emptyString)
		require.ErrorIs(t, errEmptyString, ErrEmptyArg)
		gotEmpty, ok := errors.AsType[*EmptyArgError](errEmptyString)
		require.True(t, ok)
		require.Equal(t, "caBundleString", gotEmpty.Name)

		_, errWrongString := GetRootCertsFromString("wrong string")
		require.ErrorIs(t, errWrongString, ErrNoCertsInConfig)
	})

	t.Run("CertImportValidation", func(t *testing.T) {
		pool, errCaString := GetRootCertsFromString(RSACaCertPEMString)
		require.NoError(t, errCaString)

		if diff := cmp.Diff(RSACaCertPool, pool); diff != "" {
			t.Errorf(
				"RSACACertPool vs imported Cert Pool mismatch (-want +got):\n%s",
				diff,
			)
		}
	})
}

func TestCertinfo_GetCertsFromBundle_readErrors(t *testing.T) {
	readErrorTests := []struct {
		desc       string
		certPath   string
		reader     Reader
		expectIs   error
		expectMsg  string
		expectPath string
		expectName string
	}{
		{
			desc:       "emptyString",
			certPath:   emptyString,
			reader:     inputReader,
			expectIs:   ErrEmptyArg,
			expectName: "certBundlePath",
			expectMsg:  "empty string provided as certBundlePath",
		},
		{
			desc:      "unreadableFile",
			certPath:  unreadableFile,
			reader:    mockErrReader,
			expectMsg: "error reading certificate file: unable to read file testdata/unreadable-file.txt",
		},
		{
			desc:       "wrong file",
			certPath:   RSACaCertKeyFile,
			reader:     inputReader,
			expectIs:   ErrNoCertsInFile,
			expectPath: RSACaCertKeyFile,
			expectMsg:  "no valid certificates found in file " + RSACaCertKeyFile,
		},
		{
			desc:     "nil Reader",
			certPath: RSACaCertFile,
			reader:   nil,
			expectIs: ErrNilReader,
		},
		{
			desc:      "broken cert file",
			certPath:  RSASamplePKCS8BrokenCertificate,
			reader:    inputReader,
			expectMsg: "error parsing certificate: x509: inner and outer signature algorithm identifiers don't match",
		},
	}

	for _, tt := range readErrorTests {
		t.Run(tt.desc, func(t *testing.T) {
			t.Parallel()

			_, err := GetCertsFromBundle(tt.certPath, tt.reader)
			requireCertinfoError(t, err, tt.expectIs, tt.expectMsg, tt.expectName, tt.expectPath)
		})
	}
}

func TestCertinfo_GetCertsFromBundle_import(t *testing.T) {
	t.Parallel()

	gotCerts, err := GetCertsFromBundle(RSACaCertFile, inputReader)
	require.NoError(t, err)

	wantCerts := []*x509.Certificate{RSACaCertParent}
	if diff := cmp.Diff(wantCerts, gotCerts); diff != "" {
		t.Errorf("GetCertsFromBundle certs mismatch (-want +got):\n%s", diff)
	}
}

func requireCertinfoError(
	t *testing.T,
	err error,
	expectIs error,
	expectMsg, expectName, expectPath string,
) {
	t.Helper()
	require.Error(t, err)

	if expectIs != nil {
		require.ErrorIs(t, err, expectIs)
	}

	if expectName != "" {
		got, ok := errors.AsType[*EmptyArgError](err)
		require.True(t, ok)
		require.Equal(t, expectName, got.Name)
	}

	if expectPath != "" {
		got, ok := errors.AsType[*NoCertsInFileError](err)
		require.True(t, ok)
		require.Equal(t, expectPath, got.Path)
	}

	if expectMsg != "" {
		require.EqualError(t, err, expectMsg)
	}
}

//nolint:revive
func TestCertinfo_GetKeyFromFile_inputReaderErrors(t *testing.T) {
	tests := []struct {
		desc        string
		expectError bool
		keyFile     string
		expectMsg   string
		expectIs    error
		needEnv     bool
		keyPw       string
	}{
		{
			desc:        "wrong file",
			expectError: true,
			keyFile:     RSACaCertFile,
			expectIs:    ErrUnsupportedKey,
			expectMsg:   "unsupported key format or invalid password",
		},
		{
			desc:        "emptyString",
			expectError: true,
			keyFile:     emptyString,
			expectIs:    ErrEmptyArg,
			expectMsg:   "empty string provided as keyFilePath",
		},
		{
			desc:        "No PEM encoded file",
			expectError: true,
			keyFile:     sampleTextFile,
			expectIs:    ErrPEMDecode,
			expectMsg:   "failed to decode PEM",
		},
		{
			desc:        "Plain RSA PKCS1 key import",
			expectError: false,
			keyFile:     RSASamplePKCS1PlaintextPrivateKey,
		},
		{
			desc:        "Encrypted RSA PKCS1 key import",
			expectError: false,
			keyFile:     RSASamplePKCS1EncryptedPrivateKey,
			needEnv:     true,
			keyPw:       samplePrivateKeyPassword,
		},
		{
			desc:        "Encrypted RSA PKCS1 key import with wrong password",
			expectError: true,
			expectMsg:   "PEM block decryption failed: x509: decryption password incorrect",
			keyFile:     RSASamplePKCS1EncryptedPrivateKey,
			needEnv:     true,
			keyPw:       "wrong pass",
		},
		{
			desc:        "Encrypted broken RSA PKCS1 key import",
			expectError: true,
			expectIs:    ErrUnsupportedKey,
			expectMsg:   "unsupported key format or invalid password",
			keyFile:     RSASamplePKCS1EncBrokenPrivateKey,
			needEnv:     true,
			keyPw:       samplePrivateKeyPassword,
		},
		{
			desc:        "Plain RSA/4096 PKCS8 key import",
			expectError: false,
			keyFile:     RSASamplePKCS8PlaintextPrivateKey,
		},
		{
			desc:        "Encrypted RSA/4096 PkCS8 key import",
			expectError: false,
			keyFile:     RSASamplePKCS8EncryptedPrivateKey,
			needEnv:     true,
			keyPw:       samplePrivateKeyPassword,
		},
		{
			desc:        "Encrypted broken RSA/4096 PKCS8 key import",
			expectError: true,
			expectMsg:   "PKCS8 decryption failed: pkcs8: incorrect password",
			keyFile:     RSASamplePKCS8EncBrokenPrivateKey,
			needEnv:     true,
			keyPw:       samplePrivateKeyPassword,
		},
		{
			desc:        "Plain ECDSA key import",
			expectError: false,
			keyFile:     ECDSASamplePlaintextPrivateKey,
		},
		{
			desc:        "Encrypted ECDSA key import",
			expectError: false,
			keyFile:     ECDSASampleEncryptedPrivateKey,
			needEnv:     true,
			keyPw:       samplePrivateKeyPassword,
		},
		{
			desc:        "Encrypted broken ECDSA key import",
			expectError: true,
			keyFile:     ECDSASampleEncBrokenPrivateKey,
			expectIs:    ErrUnsupportedKey,
			expectMsg:   "unsupported key format or invalid password",
			needEnv:     true,
			keyPw:       samplePrivateKeyPassword,
		},
		{
			desc:        "Plain ED25519 key import",
			expectError: false,
			keyFile:     ED25519SamplePlaintextPrivateKey,
		},
		{
			desc:        "Encrypted ED25519 key import",
			expectError: false,
			keyFile:     ED25519SampleEncryptedPrivateKey,
			needEnv:     true,
			keyPw:       samplePrivateKeyPassword,
		},
		{
			desc:        "Encrypted broken ED25519 key import",
			expectError: true,
			keyFile:     ED25519SampleEncBrokenPrivateKey,
			expectMsg:   "PKCS8 decryption failed: pkcs8: incorrect password",
			needEnv:     true,
			keyPw:       samplePrivateKeyPassword,
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			if tt.needEnv {
				t.Setenv(privateKeyPwEnvVar, tt.keyPw)
			}

			_, err := GetKeyFromFile(
				tt.keyFile,
				privateKeyPwEnvVar,
				inputReader,
			)

			if tt.expectError {
				requireCertinfoError(t, err, tt.expectIs, tt.expectMsg, "", "")
			} else {
				require.NoError(t, err)
			}
		})
	}

	t.Run("FileReadErrors", func(t *testing.T) {
		t.Parallel()

		_, errNoRead := GetKeyFromFile(
			unreadableFile,
			privateKeyPwEnvVar,
			mockErrReader,
		)
		require.Error(t, errNoRead)
		require.EqualError(t,
			errNoRead,
			"error reading private key file: unable to read file testdata/unreadable-file.txt",
		)
	})

	t.Run("nil Reader error", func(t *testing.T) {
		t.Parallel()

		_, errNoRead := GetKeyFromFile(
			RSASamplePKCS1PlaintextPrivateKey,
			privateKeyPwEnvVar,
			nil,
		)
		require.ErrorIs(t, errNoRead, ErrNilReader)
	})
}

func TestCertinfo_GetKeyFromFile(t *testing.T) {
	t.Run("Plain RSA key import", func(t *testing.T) {
		got, err := GetKeyFromFile(
			RSACaCertKeyFile,
			privateKeyPwEnvVar,
			inputReader,
		)
		require.NoError(t, err)

		if diff := cmp.Diff(RSACaCertKey, got); diff != "" {
			t.Errorf(
				"GetKeyFromFile key mismatch (-want +got):\n%s",
				diff,
			)
		}
	})
}

func TestCertinfo_ParsePrivateKey(t *testing.T) {
	// ParsePrivateKey calls getPassphraseIfNeeded
	// if the key in encrypted. It then evaluates the returned error.
	// We want to trigger that error in this test.
	// Skip passing password via ENV, this way getPassphraseIfNeeded
	// will read from stdin.
	// The mockErrReader will inject an error at this point.
	// Need to use and encrypted key's PEM
	t.Run("stdin pw read error", func(t *testing.T) {
		keyPEM, err := inputReader.ReadFile(RSASamplePKCS1EncryptedPrivateKey)
		require.NoError(t, err)

		_, err = ParsePrivateKey(
			keyPEM,
			"notSet",
			mockErrReader,
		)
		require.Error(t, err)
		assert.EqualError(t,
			err,
			"error reading passphrase: mockErrReader: unable to read password",
		)
	})
}

func TestCertinfo_IsPrivateKeyEncrypted(t *testing.T) {
	t.Run("No PEM encoded file", func(t *testing.T) {
		sampleText, err := inputReader.ReadFile(sampleTextFile)
		require.NoError(t, err)

		_, err = IsPrivateKeyEncrypted(sampleText)

		require.Error(t, err)
		assert.EqualError(t, err, "failed to decode PEM")
		require.ErrorIs(t, err, ErrPEMDecode)
	})
}

func TestCertinfo_getPassphraseIfNeeded(t *testing.T) {
	t.Run("pwEnvKey not set error", func(t *testing.T) {
		_, err := getPassphraseIfNeeded(
			true,
			emptyString,
			inputReader,
		)
		require.Error(t, err)
		require.ErrorContains(t,
			err,
			"error reading passphrase:",
		)
	})

	t.Run("pw read error", func(t *testing.T) {
		_, err := getPassphraseIfNeeded(
			true,
			emptyString,
			mockErrReader,
		)
		require.Error(t, err)
		assert.EqualError(t,
			err,
			"error reading passphrase: mockErrReader: unable to read password",
		)
	})

	t.Run("nil Reader error", func(t *testing.T) {
		_, err := getPassphraseIfNeeded(
			true,
			privateKeyPwEnvVar,
			nil,
		)
		require.ErrorIs(t, err, ErrNilReader)
	})

	t.Run("pw read success", func(t *testing.T) {
		pw, err := getPassphraseIfNeeded(
			true,
			privateKeyPwEnvVar,
			mockInputReader,
		)
		require.NoError(t, err)
		assert.Equal(t,
			[]byte(samplePrivateKeyPassword),
			pw,
		)
	})
}

func TestCertinfo_certMatchPrivateKey_matchFalse(t *testing.T) {
	incompleteCert := x509.Certificate{
		IsCA: false,
	}

	matchFalseTests := []struct {
		desc      string
		cert      *x509.Certificate
		key       crypto.PrivateKey
		expectErr bool
		expectIs  error
	}{
		{
			desc:      "uncomplete cert",
			cert:      &incompleteCert,
			key:       RSASampleCertKey,
			expectErr: true,
			expectIs:  ErrUnsupportedPublicKey,
		},

		{
			desc: "key cert mismatch",
			cert: RSACaCertParent,
			key:  RSASampleCertKey,
		},
		{
			desc: "cert nil",
			cert: nil,
			key:  RSASampleCertKey,
		},
		{
			desc: "key nil",
			cert: RSACaCertParent,
			key:  nil,
		},
		{
			desc: "key is not a signer",
			cert: RSACaCertParent,
			key:  "dummy_key",
		},
	}

	for _, tt := range matchFalseTests {
		t.Run(tt.desc, func(t *testing.T) {
			match, err := certMatchPrivateKey(
				tt.cert,
				tt.key,
			)
			if !tt.expectErr {
				require.NoError(t, err)
				assert.False(t, match)
			}

			if tt.expectErr {
				require.ErrorIs(t, err, tt.expectIs)
			}
		})
	}
}

func issueMLDSACert(t *testing.T, priv *mldsa.PrivateKey) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber:       big.NewInt(1),
		Subject:            pkix.Name{CommonName: "mldsa-test"},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(time.Hour),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		SignatureAlgorithm: x509.MLDSA44,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, priv.Public(), priv)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return cert
}

func TestCertinfo_certMatchPrivateKey_mldsa(t *testing.T) {
	t.Parallel()

	mine, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)

	other, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)

	cert := issueMLDSACert(t, mine)

	tests := []struct {
		desc  string
		key   crypto.PrivateKey
		match bool
	}{
		{
			desc:  "matching key",
			key:   mine,
			match: true,
		},
		{
			desc: "different ML-DSA key",
			key:  other,
		},
		{
			desc: "RSA key",
			key:  RSASampleCertKey,
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			tt := tc

			t.Parallel()

			match, err := certMatchPrivateKey(cert, tt.key)
			require.NoError(t, err)
			assert.Equal(t, tt.match, match)
		})
	}
}

func TestCertinfo_certMatchPrivateKey_matchTrue(t *testing.T) {
	matchTrueTests := []struct {
		desc     string
		certFile string
		keyFile  string
	}{
		{
			desc:     "RSA PKCS1",
			certFile: RSASamplePKCS1Certificate,
			keyFile:  RSASamplePKCS1PlaintextPrivateKey,
		},
		{
			desc:     "RSA PKCS8",
			certFile: RSASamplePKCS8Certificate,
			keyFile:  RSASamplePKCS8PlaintextPrivateKey,
		},
		{
			desc:     "ECDSA",
			certFile: ECDSASampleCertificate,
			keyFile:  ECDSASamplePlaintextPrivateKey,
		},
		{
			desc:     "ED25519",
			certFile: ED25519SampleCertificate,
			keyFile:  ED25519SamplePlaintextPrivateKey,
		},
	}

	for _, tt := range matchTrueTests {
		t.Run(tt.desc+" match True", func(t *testing.T) {
			certs, err := GetCertsFromBundle(
				tt.certFile,
				inputReader,
			)
			require.NoError(t, err)

			key, err := GetKeyFromFile(
				tt.keyFile,
				privateKeyPwEnvVar,
				inputReader,
			)
			require.NoError(t, err)

			match, err := certMatchPrivateKey(
				certs[0],
				key,
			)
			require.NoError(t, err)
			assert.True(t, match)
		})
	}
}

func TestCertinfo_PrintCertInfo(t *testing.T) {
	t.Run("RSA Sample Certificate", func(t *testing.T) {
		buffer := bytes.Buffer{}
		PrintCertInfo(RSACaCertParent, 1, &buffer)

		got := buffer.String()

		require.Contains(t, got, "Subject")
		require.Contains(t, got, "Issuer")
		require.Contains(t, got, "Valid From:")
		require.Contains(t, got, "Valid To:")
		require.Contains(t, got, "DNS Names:")
		require.Contains(t, got, "Is CA:")
		require.Contains(t, got, "Serial Number:")
		require.Contains(t, got, "Public Key Algorithm:")
		require.Contains(t, got, "Signature Algorithm:")
	})
}
