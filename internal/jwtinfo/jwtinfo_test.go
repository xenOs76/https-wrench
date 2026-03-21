package jwtinfo

import (
	"bytes"
	"encoding/base64"
	"io"
	"maps"
	"testing"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestParseRequestJSONValues(t *testing.T) {
	inputMap := make(map[string]string)
	inputMap["testKey"] = "testValue"

	mapToValidJSON := make(map[string]string)
	mapToValidJSON["testKey2"] = "testValue2"
	mapToValidJSON["testKey3"] = "testValue3"

	tests := []struct {
		name         string
		jsonStr      string
		jsonRefMap   map[string]string
		requireError bool
		errorMsg     string
	}{
		{
			name:         "validJson",
			jsonStr:      "{\"testKey2\":\"testValue2\", \"testKey3\":\"testValue3\"}",
			jsonRefMap:   mapToValidJSON,
			requireError: false,
		},
		{
			name:         "invalidJson",
			jsonStr:      "{\"testKey2  :\"testValue2\", \"testKey3\":\"testValue3\"}",
			jsonRefMap:   mapToValidJSON,
			requireError: true,
			errorMsg:     "unable to parse Json request values: invalid character 't' after object key",
		},
		{
			name:         "emptyJsonString",
			jsonStr:      "",
			jsonRefMap:   mapToValidJSON,
			requireError: true,
			errorMsg:     "empty string provided as JSON encoded request values",
		},
	}
	for _, tc := range tests {
		tt := tc
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			outputMap, err := ParseRequestJSONValues(
				tt.jsonStr,
				inputMap,
			)

			if tt.requireError {
				require.Error(t, err)
				require.ErrorContains(t, err, tt.errorMsg)

				return
			}

			require.NoError(t, err)

			sourceMaps := make(map[string]string)
			maps.Copy(sourceMaps, inputMap)
			maps.Copy(sourceMaps, tt.jsonRefMap)

			for k := range outputMap {
				_, ok := sourceMaps[k]
				require.True(
					t,
					ok,
					"outputMap must contain all keys from inputMap and tt.jsonRefMap",
				)
				require.Equal(
					t,
					sourceMaps[k],
					outputMap[k],
					"outputMap must contain all values from inputMap and tt.jsonRefMap",
				)
			}
		})
	}
}

func TestRequestToken(t *testing.T) {
	tests := []struct {
		name     string
		user     string
		pass     string
		scope    string
		expError bool
	}{
		{
			name:  "applicationJwt",
			user:  "test",
			pass:  "known",
			scope: "default",
		},

		{
			name:     "appJwtInvalid",
			user:     "test",
			pass:     "known",
			scope:    "appJwtInvalid",
			expError: true,
		},

		{
			name:     "emptyReqValues",
			scope:    "emptyValuesMap",
			expError: true,
		},

		{
			name:     "emptyReqUrl",
			user:     "test",
			pass:     "known",
			scope:    "emptyReqUrl",
			expError: true,
		},

		{
			name:     "wrongReqUrl",
			user:     "test",
			pass:     "known",
			scope:    "wrongReqUrl",
			expError: true,
		},

		{
			name:     "wrongReqParam",
			user:     "test",
			pass:     "known",
			scope:    "wrongReqParam",
			expError: true,
		},

		{
			name:  "applicationJson",
			user:  "test",
			pass:  "known",
			scope: "applicationJson",
		},

		{
			name:     "appJsonInvalid",
			user:     "test",
			pass:     "known",
			scope:    "appJsonInvalid",
			expError: true,
		},

		{
			name:     "wrongPass",
			user:     "test",
			pass:     "wrong",
			scope:    "applicationJson",
			expError: true,
		},
	}
	for _, tc := range tests {
		tt := tc
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server, err := NewJwtTestServer()

			require.NoError(t, err)

			defer server.Close()

			client := server.Client()
			serverRoot := server.URL

			serverJwtEndpoint := serverRoot + "/jwt"

			if tt.scope == "emptyReqUrl" {
				serverJwtEndpoint = ""
			}

			if tt.scope == "wrongReqUrl" {
				serverJwtEndpoint = "https://does.not.exist/wrong"
			}

			if tt.scope == "wrongReqParam" {
				serverJwtEndpoint = "https://local$%#@@&host/wrongUrl"
			}

			reqValues := make(map[string]string)
			if tt.scope != "emptyValuesMap" {
				reqValues["user"] = tt.user
				reqValues["pass"] = tt.pass
				reqValues["scope"] = tt.scope
			}

			_, err = RequestToken(
				serverJwtEndpoint,
				reqValues,
				client,
				io.ReadAll,
			)

			if tt.expError {
				require.Error(
					t,
					err,
					"RequestToken - expected error: %s",
					err,
				)

				return
			}

			require.NoError(
				t,
				err,
				"RequestToken error: %s",
				err,
			)

			// godump.Dump(td)
		})
	}
}

func TestParseTokenData(t *testing.T) {
	tests := []struct {
		name        string
		user        string
		pass        string
		scope       string
		bodyReader  allReader
		expError    bool
		expReqError bool
	}{
		{
			name:       "applicationJwt",
			user:       "test",
			pass:       "known",
			bodyReader: io.ReadAll,
			scope:      "default",
		},

		{
			name:       "applicationJson",
			user:       "test",
			pass:       "known",
			bodyReader: io.ReadAll,
			scope:      "applicationJson",
		},
		{
			name:        "readError",
			user:        "test",
			pass:        "known",
			bodyReader:  mockErrReader.ReadAll,
			scope:       "applicationJson",
			expReqError: true,
		},

		{
			name:       "jwksEmpty",
			user:       "test",
			pass:       "known",
			bodyReader: io.ReadAll,
			scope:      "jwksEmpty",
		},
		{
			name:       "jwksFaulty",
			user:       "test",
			pass:       "known",
			bodyReader: io.ReadAll,
			scope:      "jwksFaulty",
		},
	}

	for _, tc := range tests {
		tt := tc

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server, err := NewJwtTestServer()

			require.NoError(t, err)

			defer server.Close()

			client := server.Client()
			serverRoot := server.URL
			serverJwtEndpoint := serverRoot + "/jwt"
			serverJwksEndpoint := serverRoot + "/jwks.json"
			serverJwksEmptyEndpoint := serverRoot + "/jwksEmpty.json"
			serverJwksFaultyEndpoint := serverRoot + "/jwksFaulty.json"

			rootResp, err := client.Get(serverRoot)
			require.NoError(t, err)

			rootBody, err := io.ReadAll(rootResp.Body)
			require.NoError(t, err)
			require.Contains(t, string(rootBody), "root handler")

			defer rootResp.Body.Close()

			reqValues := make(map[string]string)
			reqValues["user"] = tt.user
			reqValues["pass"] = tt.pass
			reqValues["scope"] = tt.scope

			td, err := RequestToken(
				serverJwtEndpoint,
				reqValues,
				client,
				tt.bodyReader,
			)

			if !tt.expReqError {
				require.NoError(
					t,
					err,
					"RequestToken error: %s", err,
				)
			}

			if tt.expReqError {
				require.ErrorContains(
					t,
					err,
					"unable to read body: mock Reader error",
				)

				return
			}

			keyfuncOverrideTesting := keyfunc.Override{
				Client: server.Client(),
			}

			_, err = ParseTokenData(
				td,
				"",
				keyfuncOverrideTesting,
			)
			require.NoError(t, err)

			if tt.scope == "jwksEmpty" {
				respJwksEmpty, errEmpty := server.Client().Get(serverJwksEmptyEndpoint)
				require.NoError(t, errEmpty)

				defer respJwksEmpty.Body.Close()

				respJwksEmptyBody, errEmptyBody := io.ReadAll(respJwksEmpty.Body)
				require.NoError(t, errEmptyBody)

				require.Contains(
					t,
					string(respJwksEmptyBody),
					"{}",
				)

				_, err = ParseTokenData(
					td,
					serverJwksEmptyEndpoint,
					keyfuncOverrideTesting,
				)
				require.ErrorContains(
					t,
					err,
					"keyfunc returned empty verification key set",
				)

				return
			}

			if tt.scope == "jwksFaulty" {
				respJwksFaulty, errFaulty := server.Client().Get(serverJwksFaultyEndpoint)
				require.NoError(t, errFaulty)

				defer respJwksFaulty.Body.Close()

				respJwksFaultyBody, errFaultyBody := io.ReadAll(respJwksFaulty.Body)
				require.NoError(t, errFaultyBody)

				require.Contains(
					t,
					string(respJwksFaultyBody),
					"UniqueKeyID1",
				)

				_, err = ParseTokenData(
					td,
					serverJwksFaultyEndpoint,
					keyfuncOverrideTesting,
				)
				require.ErrorContains(
					t,
					err,
					"keyfunc returned empty verification key set",
				)

				return
			}

			tokenVerified, err := ParseTokenData(
				td,
				serverJwksEndpoint,
				keyfuncOverrideTesting,
			)
			require.NoError(t, err)
			require.True(
				t,
				tokenVerified.Valid,
				"JWT token must be valid",
			)
		})
	}
}

func TestParseTokenData_Errors(t *testing.T) {
	t.Run("ParseUnverifiedError", func(t *testing.T) {
		t.Parallel()

		td := JwtTokenData{AccessToken: "notValidString"}

		_, err := ParseTokenData(
			td,
			"",
			keyfunc.Override{},
		)
		require.ErrorContains(
			t,
			err,
			"token is malformed: token contains an invalid number of segments",
		)
	})

	t.Run("WrongJwksURL", func(t *testing.T) {
		t.Parallel()

		token, err := createToken("demo")
		require.NoError(t, err)

		td := JwtTokenData{AccessToken: token}

		_, err = ParseTokenData(
			td,
			"https://localhost:54321/jkws.wrong.json",
			keyfunc.Override{},
		)
		require.ErrorContains(
			t,
			err,
			"keyfunc returned empty verification key set",
		)
	})

	t.Run("JwksURIParseError", func(t *testing.T) {
		t.Parallel()

		token, err := createToken("demo")
		require.NoError(t, err)

		td := JwtTokenData{AccessToken: token}

		_, err = ParseTokenData(
			td,
			"https://loca#$%^/jkws.json",
			keyfunc.Override{},
		)
		require.ErrorContains(
			t,
			err,
			"failed to create JWK Set from resource at URL",
		)
	})
}

func TestDecodeBase64(t *testing.T) {
	notThreeDotted := "notThreeDottedBase64CompliantString"

	validJSONHeader := "{\"header\":\"validHeader\"}"
	validJSONClaims := "{\"claims\":\"validClaim\"}"

	invalidJSONHeader := "{\"headerNoQuote:\"invalidHeader\"}"
	invalidJSONClaims := "{\"claimsNoQuote:\"validClaim\"}"

	b64notThreeDotted := base64.RawURLEncoding.EncodeToString([]byte(notThreeDotted))

	b64ValidJSONHeader := base64.RawURLEncoding.EncodeToString([]byte(validJSONHeader))
	b64ValidJSONClaims := base64.RawURLEncoding.EncodeToString([]byte(validJSONClaims))

	b64InvalidJSONHeader := base64.RawURLEncoding.EncodeToString([]byte(invalidJSONHeader))
	b64InvalidJSONClaims := base64.RawURLEncoding.EncodeToString([]byte(invalidJSONClaims))

	notB64JSONEncodedHeader := "{\"header\":\"invalidBase64$%^&^&\"}"
	notB64JSONEncodedClaims := "{\"claims\":\"invalidBase64$%^&^&\"}"

	signaturePlaceholder := "signature placeholder"

	invalidB64HeaderTokenString := notB64JSONEncodedHeader + "." + b64ValidJSONClaims + "." + signaturePlaceholder
	invalidB64ClaimsTokenString := b64ValidJSONHeader + "." + notB64JSONEncodedClaims + "." + signaturePlaceholder

	invalidJSONHeaderTokenString := b64InvalidJSONHeader + "." + b64ValidJSONClaims + "." + signaturePlaceholder
	invalidJSONClaimsTokenString := b64ValidJSONHeader + "." + b64InvalidJSONClaims + "." + signaturePlaceholder

	tests := []struct {
		name        string
		tokenString string
		errMsg      string
	}{
		{
			name:        "not three dotted string",
			tokenString: b64notThreeDotted,
			errMsg:      "invalid three dotted JWT format in",
		},
		{
			name:        "invalid base64 header",
			tokenString: invalidB64HeaderTokenString,
			errMsg:      "unable to decode base64 header from",
		},

		{
			name:        "invalid base64 claims",
			tokenString: invalidB64ClaimsTokenString,
			errMsg:      "unable to decode base64 claims from",
		},

		{
			name:        "invalid JSON header",
			tokenString: invalidJSONHeaderTokenString,
			errMsg:      "invalid JSON found in header from",
		},
		{
			name:        "invalid JSON claims",
			tokenString: invalidJSONClaimsTokenString,
			errMsg:      "invalid JSON found in claims from",
		},
	}

	for _, tc := range tests {
		tt := tc

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			accessTokenRaw, err := createToken("demo")
			require.NoError(t, err)

			td := JwtTokenData{AccessToken: accessTokenRaw}
			err = td.DecodeBase64()
			require.NoError(t, err)

			require.Contains(t, string(td.AccessTokenClaims), "demo")
			require.NoError(t, err)

			tdAccessTokenTest := td
			tdAccessTokenTest.AccessToken = tt.tokenString
			err = tdAccessTokenTest.DecodeBase64()
			require.ErrorContains(t, err, tt.errMsg)

			refreshTokenRaw, err := createToken("demo")
			require.NoError(t, err)

			tdR := JwtTokenData{RefreshToken: refreshTokenRaw}
			err = tdR.DecodeBase64()
			require.NoError(t, err)

			tdRefreshTokenTest := tdR
			tdRefreshTokenTest.RefreshToken = tt.tokenString
			err = tdRefreshTokenTest.DecodeBase64()
			require.ErrorContains(t, err, tt.errMsg)
		})
	}
}

func TestUnmarshallTokenTimeClaims(t *testing.T) {
	t.Run("unmarshallTokenTimeClaims", func(t *testing.T) {
		t.Parallel()

		var jtd JwtTokenData

		var err error

		now := time.Now()
		inOneMinute := time.Now().Add(time.Minute * 1)
		expiresAt := jwt.NewNumericDate(inOneMinute)
		issuedAt := jwt.NewNumericDate(now)

		testTimeClaims := make(map[string]time.Time)
		testTimeClaims["iat"] = now
		testTimeClaims["exp"] = inOneMinute

		token := jwt.New(jwt.GetSigningMethod("RS256"))

		token.Claims = &CustomClaimsExample{
			jwt.RegisteredClaims{
				ExpiresAt: expiresAt,
				IssuedAt:  issuedAt,
			},
			"level1",
			CustomerInfo{"demo", "human"},
		}

		jtd.AccessToken, err = token.SignedString(signKey)
		require.NoError(t, err)

		err = jtd.DecodeBase64()
		require.NoError(t, err)

		claimsMap, err := unmarshallTokenTimeClaims(
			jtd.AccessTokenClaims,
		)
		require.NoError(t, err)

		_, ok := claimsMap["iat"]
		require.True(t, ok, "key iat (Issued At) must exist")

		_, ok = claimsMap["exp"]
		require.True(t, ok, "key exp (Expiration Time) must exist")

		for k, testTimeClaim := range testTimeClaims {
			dateUtcString := testTimeClaim.UTC().Format(time.UnixDate)
			require.Equal(t, dateUtcString, claimsMap[k])
		}
	})
}

func TestUnmarshallTokenTimeClaims_MapErrors(t *testing.T) {
	invalidJSONClaims := "can not unmarshal"

	noIatClaims := "{\"exp\":1}"
	iatStringClaims := "{\"iat\":\"now\"}"

	noExpClaims := "{\"iat\":1}"
	expStringClaims := "{\"exp\":\"now\", \"iat\":1}"

	tests := []struct {
		name   string
		claims []byte
		errMsg string
	}{
		{
			name:   "invalid JSON",
			claims: []byte(invalidJSONClaims),
			errMsg: "unable to unmarshall claims",
		},
		{
			name:   "missing Issued At",
			claims: []byte(noIatClaims),
			errMsg: "unable to find Issued At (iat) in token Claims",
		},
		{
			name:   "not numeric Issued At",
			claims: []byte(iatStringClaims),
			errMsg: "Issued At (iat) claim is not a numeric timestamp",
		},

		{
			name:   "claims no Expiration Time",
			claims: []byte(noExpClaims),
			errMsg: "unable to find Expiration Time (exp) in token Claims",
		},
		{
			name:   "not numeric Expiration Time",
			claims: []byte(expStringClaims),
			errMsg: "Expiration Time (exp) claim is not a numeric timestamp",
		},
	}

	for _, test := range tests {
		tt := test
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := unmarshallTokenTimeClaims(tt.claims)
			require.ErrorContains(t, err, tt.errMsg)
		})
	}
}

func TestPrintTokenInfo(t *testing.T) {
	tests := []struct {
		name        string
		user        string
		pass        string
		scope       string
		bodyReader  allReader
		expError    bool
		expReqError bool
	}{
		{
			name:       "default case",
			user:       "test",
			pass:       "known",
			bodyReader: io.ReadAll,
			scope:      "default",
		},
	}

	for _, tc := range tests {
		tt := tc

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server, err := NewJwtTestServer()

			require.NoError(t, err)

			defer server.Close()

			client := server.Client()
			serverRoot := server.URL
			serverJwtEndpoint := serverRoot + "/jwt"
			serverJwksEndpoint := serverRoot + "/jwks.json"

			rootResp, err := client.Get(serverRoot)
			require.NoError(t, err)

			rootBody, err := io.ReadAll(rootResp.Body)
			require.NoError(t, err)
			require.Contains(t, string(rootBody), "root handler")

			defer rootResp.Body.Close()

			reqValues := make(map[string]string)
			reqValues["user"] = tt.user
			reqValues["pass"] = tt.pass
			reqValues["scope"] = tt.scope

			td, err := RequestToken(
				serverJwtEndpoint,
				reqValues,
				client,
				tt.bodyReader,
			)
			require.NoError(t, err)

			keyfuncOverrideTesting := keyfunc.Override{
				Client: server.Client(),
			}

			tokenVerified, err := ParseTokenData(
				td,
				serverJwksEndpoint,
				keyfuncOverrideTesting,
			)
			require.NoError(t, err)
			require.True(
				t,
				tokenVerified.Valid,
				"JWT token must be valid",
			)

			err = td.DecodeBase64()
			require.NoError(t, err)

			buffer := bytes.Buffer{}
			err = PrintTokenInfo(td, &buffer)
			require.NoError(t, err)

			got := buffer.String()

			stringsToCheck := []string{
				"JwtInfo",
				"Header",
				"Claims",
				"alg",
				"RS256",
				"typ",
				"JWT",
				"Issued At",
				"Expiration Time",
				"exp",
				"iat",
			}

			for _, outStr := range stringsToCheck {
				require.Contains(t, got, outStr)
			}
		})
	}
}
