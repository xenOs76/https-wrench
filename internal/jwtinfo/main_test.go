//
// JwtInfo testing resource
//
// Refs:
// * https://github.com/golang-jwt/jwt/blob/main/http_example_test.go
//

package jwtinfo

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/golang-jwt/jwt/v5"
)

type (
	CustomerInfo struct {
		Name string
		Kind string
	}

	CustomClaimsExample struct {
		jwt.RegisteredClaims
		TokenType string
		CustomerInfo
	}

	MockErrReader struct{}
)

const (
	rsaPrivKeyPath = "./testdata/rsa-pkcs8-plaintext-private-key.pem"
)

var (
	// rsaSignKeyPriv *rsa.PrivateKey
	signKey       *rsa.PrivateKey
	mockErrReader MockErrReader
)

func (MockErrReader) ReadAll(r io.Reader) ([]byte, error) {
	return nil, errors.New("mock Reader error")
}

func TestMain(m *testing.M) {
	signBytes, err := os.ReadFile(rsaPrivKeyPath)
	fatal(err)

	signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	fatal(err)

	m.Run()
}

func fatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func createToken(user string) (string, error) {
	// create a signer for rsa 256
	t := jwt.New(jwt.GetSigningMethod("RS256"))

	// set our claims
	t.Claims = &CustomClaimsExample{
		jwt.RegisteredClaims{
			// set the expire time
			// see https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 1)),
		},
		"level1",
		CustomerInfo{user, "human"},
	}

	// Creat token string
	return t.SignedString(signKey)
}

func rootHandler(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprintln(w, "JWT testing server: root handler")
}

func testHandler(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprintln(w, "JWT testing server: test handler")
}

func jwksHandler(writer http.ResponseWriter, request *http.Request) {
	ctx := context.Background()
	jwkSet := jwkset.NewMemoryStorage()

	// Create the JWK options.
	metadata := jwkset.JWKMetadataOptions{
		KID: "rsa-key-id", // Not technically required, but is required for JWK Set operations using this package.
	}
	options := jwkset.JWKOptions{
		Metadata: metadata,
	}

	// Create the JWK from the key and options.
	jwk, err := jwkset.NewJWKFromKey(signKey, options)
	if err != nil {
		fmt.Printf("failed to create JWK from key: %s", err)
	}

	// Write the key to the JWK Set storage.
	err = jwkSet.KeyWrite(ctx, jwk)
	if err != nil {
		fmt.Printf("failed to store RSA key: %s", err)
	}

	response, err := jwkSet.JSONPublic(request.Context())
	if err != nil {
		fmt.Printf("failed to get JWK Set JSON: %s", err)
		writer.WriteHeader(http.StatusInternalServerError)

		return
	}

	writer.Header().Set("Content-Type", "application/json")
	_, _ = writer.Write(response)
}

func jwksFaultyHandler(writer http.ResponseWriter, _ *http.Request) {
	// Jwks file created with:
	// jwkset testdata/rsa-pkcs8-plaintext-private-key.pem

	// validJwksFile := "testdata/jwkset-from-rsa-private-key-valid.json"
	corruptedJwksFile := "testdata/jwkset-from-rsa-private-key-corrupted.json"
	jwksContent, _ := os.ReadFile(corruptedJwksFile)

	writer.Header().Set("Content-Type", "application/json")
	_, _ = writer.Write(jwksContent)
}

func jwksEmptyHandler(writer http.ResponseWriter, _ *http.Request) {
	respString := "{}"

	writer.Header().Set("Content-Type", "application/json")
	_, _ = writer.Write([]byte(respString))
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	// make sure its post
	if r.Method != "POST" {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintln(w, "No POST", r.Method)

		return
	}

	user := r.FormValue("user")
	pass := r.FormValue("pass")
	scope := r.FormValue("scope")

	// log.Printf("Authenticate: user[%s] pass[%s]\n", user, pass)

	if user != "test" || pass != "known" {
		w.WriteHeader(http.StatusForbidden)

		_, _ = fmt.Fprintln(w, "Wrong info")

		return
	}

	tokenString, err := createToken(user)
	tokenJSONString := fmt.Sprintf(
		"{\"access_token\":\"%s\"}",
		tokenString,
	)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)

		_, _ = fmt.Fprintln(w, "Sorry, error while Signing Token!")

		log.Printf("Token Signing error: %v\n", err)

		return
	}

	if scope == "applicationJson" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, tokenJSONString)

		return
	}

	if scope == "appJsonInvalid" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, "{\"test\":\"invalid}")

		return
	}

	if scope == "appJwtInvalid" {
		w.Header().Set("Content-Type", "application/jwt")
		// w.WriteHeader(http.StatusOK)
		fmt.Println("JWT invalid")
		// _, _ = fmt.Fprintln(w, "")

		return
	}

	w.Header().Set("Content-Type", "application/jwt")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintln(w, tokenString)
}

func NewJwtTestServer() (*httptest.Server, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", rootHandler)
	mux.HandleFunc("/jwt", authHandler)
	mux.HandleFunc("/jwks.json", jwksHandler)
	mux.HandleFunc("/jwksFaulty.json", jwksFaultyHandler)
	mux.HandleFunc("/jwksEmpty.json", jwksEmptyHandler)

	ts := httptest.NewUnstartedServer(mux)
	ts.EnableHTTP2 = true
	ts.StartTLS()

	return ts, nil
}
