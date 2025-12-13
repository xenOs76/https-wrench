package certinfo

import (
	"crypto/x509"
	"testing"

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
		assert.Equal(t,
			"empty string provided as caBundlePath",
			errEmptyString.Error(),
		)

		_, errNoRead := GetRootCertsFromFile(
			unreadableFile,
			mockErrReader,
		)
		require.Error(t, errNoRead)
		assert.Equal(t,
			"failed to read CA bundle file: unable to read file testdata/unreadable-file.txt",
			errNoRead.Error(),
		)

		_, errWrongFile := GetRootCertsFromFile(
			RSACaCertKeyFile,
			inputReader,
		)
		require.Error(t, errWrongFile)
		assert.Equal(t,
			"unable to create CertPool from file",
			errWrongFile.Error(),
		)
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
}

func TestCertinfo_GetRootCertsFromString(t *testing.T) {
	t.Run("ReadErrors", func(t *testing.T) {
		t.Parallel()

		_, errEmptyString := GetRootCertsFromString(emptyString)
		require.Error(t, errEmptyString)
		assert.Equal(t,
			"empty string provided as caBundleString",
			errEmptyString.Error(),
		)

		_, errWrongString := GetRootCertsFromString("wrong string")
		require.Error(t, errWrongString)
		assert.Equal(t,
			"no valid certs in caBundle config string",
			errWrongString.Error())
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

func TestCertinfo_GetCertsFromBundle(t *testing.T) {
	t.Run("FileReadErrors", func(t *testing.T) {
		t.Parallel()

		_, errEmptyString := GetCertsFromBundle(
			emptyString,
			inputReader,
		)
		require.Error(t, errEmptyString)
		assert.Equal(t,
			"empty string provided as caBundlePath",
			errEmptyString.Error(),
		)

		_, errNoRead := GetCertsFromBundle(
			unreadableFile,
			mockErrReader,
		)
		require.Error(t, errNoRead)
		assert.Equal(t,
			"error reading certificate file: unable to read file testdata/unreadable-file.txt",
			errNoRead.Error(),
		)

		_, errWrongFile := GetCertsFromBundle(
			RSACaCertKeyFile,
			inputReader,
		)
		require.Error(t, errWrongFile)
		assert.Equal(t,
			"no valid certificates found in file "+RSACaCertKeyFile,
			errWrongFile.Error(),
		)
	})

	t.Run("CertImportValidation", func(t *testing.T) {
		gotCerts, errCaString := GetCertsFromBundle(
			RSACaCertFile,
			inputReader,
		)
		require.NoError(t, errCaString)

		wantCerts := []*x509.Certificate{RSACaCertParent}

		if diff := cmp.Diff(wantCerts, gotCerts); diff != "" {
			t.Errorf(
				"GetCertsFromBundle certs mismatch (-want +got):\n%s",
				diff,
			)
		}
	})
}

func TestCertinfo_GetKeyFromFile(t *testing.T) {
	t.Run("FileReadErrors", func(t *testing.T) {
		t.Parallel()

		_, errEmptyString := GetKeyFromFile(
			emptyString,
			inputReader,
		)
		require.Error(t, errEmptyString)
		assert.Equal(t,
			"empty string provided as keyFilePath",
			errEmptyString.Error(),
		)

		_, errNoRead := GetKeyFromFile(
			unreadableFile,
			mockErrReader,
		)
		require.Error(t, errNoRead)
		assert.Equal(t,
			"unable to read file testdata/unreadable-file.txt",
			errNoRead.Error(),
		)

		_, errWrongFile := GetKeyFromFile(
			RSACaCertFile,
			inputReader,
		)
		require.Error(t, errWrongFile)
		assert.Equal(t,
			"unsupported key format or invalid password",
			errWrongFile.Error(),
		)
	})

	t.Run("Plain RSA key import", func(t *testing.T) {
		got, err := GetKeyFromFile(
			RSACaCertKeyFile,
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

	t.Run("No PEM encoded text import", func(t *testing.T) {
		_, err := GetKeyFromFile(
			sampleTextFile,
			inputReader,
		)
		require.Error(t, err)
		assert.EqualError(t, err, "failed to decode PEM")
	})

	t.Run("Plain RSA PKCS1 key import", func(t *testing.T) {
		_, err := GetKeyFromFile(
			RSASamplePKCS1PlaintextPrivateKey,
			inputReader,
		)
		require.NoError(t, err)
	})

	t.Run("Encrypted RSA PKCS1 key import", func(t *testing.T) {
		t.Setenv(privateKeyPwEnvVar, samplePrivateKeyPassword)

		_, err := GetKeyFromFile(
			RSASamplePKCS1EncryptedPrivateKey,
			inputReader,
		)
		require.NoError(t, err)
	})

	t.Run("Encrypted RSA PKCS1 key import with wrong password", func(t *testing.T) {
		t.Setenv(privateKeyPwEnvVar, "wrong password")

		_, err := GetKeyFromFile(
			RSASamplePKCS1EncryptedPrivateKey,
			inputReader,
		)
		require.Error(t, err)
		assert.EqualError(t,
			err,
			"PEM block decryption failed: x509: decryption password incorrect",
		)
	})

	t.Run("Encrypted broken RSA PKCS1 key import", func(t *testing.T) {
		t.Setenv(privateKeyPwEnvVar, samplePrivateKeyPassword)

		_, err := GetKeyFromFile(
			RSASamplePKCS1EncBrokenPrivateKey,
			inputReader,
		)
		require.Error(t, err)
		require.Equal(t,
			"unsupported key format or invalid password",
			err.Error())
	})

	t.Run("Plain RSA/4096 PKCS8 key import", func(t *testing.T) {
		_, err := GetKeyFromFile(
			RSASamplePKCS8PlaintextPrivateKey,
			inputReader,
		)
		require.NoError(t, err)
	})

	t.Run("Encrypted RSA/4096 PKCS8 key import", func(t *testing.T) {
		t.Setenv(privateKeyPwEnvVar, samplePrivateKeyPassword)

		_, err := GetKeyFromFile(
			RSASamplePKCS8EncryptedPrivateKey,
			inputReader,
		)
		require.NoError(t, err)
	})

	t.Run("Encrypted broken RSA/4096 PKCS8 key import", func(t *testing.T) {
		t.Setenv(privateKeyPwEnvVar, samplePrivateKeyPassword)

		_, err := GetKeyFromFile(
			RSASamplePKCS8EncBrokenPrivateKey,
			inputReader,
		)
		require.Error(t, err)
		assert.Equal(t,
			"PKCS8 decryption failed: pkcs8: incorrect password",
			err.Error())
	})

	t.Run("Plain ECDSA key import", func(t *testing.T) {
		_, err := GetKeyFromFile(
			ECDSASamplePlaintextPrivateKey,
			inputReader,
		)
		require.NoError(t, err)
	})

	t.Run("Encrypted ECDSA key import", func(t *testing.T) {
		t.Setenv(privateKeyPwEnvVar, samplePrivateKeyPassword)

		_, err := GetKeyFromFile(
			ECDSASampleEncryptedPrivateKey,
			inputReader,
		)
		require.NoError(t, err)
	})

	t.Run("Encrypted broken ECDSA key import", func(t *testing.T) {
		t.Setenv(privateKeyPwEnvVar, samplePrivateKeyPassword)

		_, err := GetKeyFromFile(
			ECDSASampleEncBrokenPrivateKey,
			inputReader,
		)
		require.Error(t, err)
		assert.Equal(t,
			"unsupported key format or invalid password",
			err.Error())
	})

	t.Run("Plain ED25519 key import", func(t *testing.T) {
		_, err := GetKeyFromFile(
			ED25519SamplePlaintextPrivateKey,
			inputReader,
		)
		require.NoError(t, err)
	})

	t.Run("Encrypted ED25519 key import", func(t *testing.T) {
		t.Setenv(privateKeyPwEnvVar, samplePrivateKeyPassword)

		_, err := GetKeyFromFile(
			ED25519SampleEncryptedPrivateKey,
			inputReader,
		)
		require.NoError(t, err)
	})

	t.Run("Encrypted broken ED25519 key import", func(t *testing.T) {
		t.Setenv(privateKeyPwEnvVar, samplePrivateKeyPassword)

		_, err := GetKeyFromFile(
			ED25519SampleEncBrokenPrivateKey,
			inputReader,
		)
		require.Error(t, err)
		assert.Equal(t,
			"PKCS8 decryption failed: pkcs8: incorrect password",
			err.Error())
	})
}

func TestCertinfo_ParsePrivateKey(t *testing.T) {
	// ParsePrivateKey calls getPassphraseIfNeeded
	// if the key in encrypted. It then evaluates the returned error.
	// We want to trigger that error in this test.
	// Skip passing password via ENV, this way getPassphraseIfNeeded
	// will read from stdin.
	// Need to use and encrypted key's PEM
	// t.Run("stdin pw read error", func(t *testing.T) {
	// 	key, err := GetKeyFromFile(
	// 		RSASamplePKCS1EncryptedPrivateKey,
	// 		inputReader,
	// 	)
	// 	require.NoError(t, err)
	//
	// 	var i any = key
	//
	// 	rsaKey, ok := i.(*rsa.PrivateKey)
	//
	// 	require.True(t, ok, "the key must be of type *rsa.PrivateKey")
	//
	// 	rsaKeyPEM := RSAPrivateKeyToPEM(rsaKey)
	//
	// 	_, err = ParsePrivateKey(
	// 		rsaKeyPEM,
	// 		privateKeyPwEnvVar,
	// 		mockErrReader,
	// 	)
	// 	require.Error(t, err)
	// 	assert.EqualError(t,
	// 		err,
	// 		"error reading passphrase: inappropriate ioctl for device",
	// 	)
	// })
}

func TestCertinfo_IsPrivateKeyEncrypted(t *testing.T) {
	t.Run("No PEM encoded file", func(t *testing.T) {
		sampleText, err := inputReader.ReadFile(sampleTextFile)
		require.NoError(t, err)

		_, err = IsPrivateKeyEncrypted(sampleText)

		require.Error(t, err)
		assert.EqualError(t, err, "failed to decode PEM")
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
		assert.EqualError(t,
			err,
			"error reading passphrase: inappropriate ioctl for device",
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

func TestCertinfo_certMatchPrivateKey(t *testing.T) {
	t.Run("RSA PKCS8 match True", func(t *testing.T) {
		match, err := certMatchPrivateKey(
			RSACaCertParent,
			RSACaCertKey,
		)
		require.NoError(t, err)
		assert.True(t, match, "matchTrue")
	})

	t.Run("RSA PKCS1 match True", func(t *testing.T) {
		certs, err := GetCertsFromBundle(
			RSASamplePKCS1Certificate,
			inputReader,
		)
		require.NoError(t, err)

		key, err := GetKeyFromFile(
			RSASamplePKCS1PlaintextPrivateKey,
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

	t.Run("ECDSA match True", func(t *testing.T) {
		certs, err := GetCertsFromBundle(
			ECDSASampleCertificate,
			inputReader,
		)
		require.NoError(t, err)

		key, err := GetKeyFromFile(
			ECDSASamplePlaintextPrivateKey,
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

	t.Run("ED25519 match True", func(t *testing.T) {
		certs, err := GetCertsFromBundle(
			ED25519SampleCertificate,
			inputReader,
		)
		require.NoError(t, err)

		key, err := GetKeyFromFile(
			ED25519SamplePlaintextPrivateKey,
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

	t.Run("matchFalse", func(t *testing.T) {
		match, err := certMatchPrivateKey(
			RSACaCertParent,
			RSASampleCertKey,
		)
		require.NoError(t, err)
		assert.False(t, match)
	})

	t.Run("Cert nil False match", func(t *testing.T) {
		match, err := certMatchPrivateKey(
			nil,
			RSASampleCertKey,
		)
		require.NoError(t, err)
		assert.False(t, match)
	})

	t.Run("Key nil False match", func(t *testing.T) {
		match, err := certMatchPrivateKey(
			RSACaCertParent,
			nil,
		)
		require.NoError(t, err)
		assert.False(t, match)
	})
}
