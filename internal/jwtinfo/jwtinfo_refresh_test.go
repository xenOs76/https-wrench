package jwtinfo

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type mockTransport struct {
	roundTripFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.roundTripFunc(req)
}

func TestJwtTokenData_GetTimeClaims(t *testing.T) {
	exp := time.Now().Add(1 * time.Hour).Unix()
	iat := time.Now().Unix()

	claims := map[string]any{
		"exp": float64(exp),
		"iat": float64(iat),
	}

	claimsBytes, err := json.Marshal(claims)
	require.NoError(t, err)

	jtd := JwtTokenData{
		AccessTokenClaims: claimsBytes,
	}

	gotExp, err := jtd.GetExpiration()
	require.NoError(t, err)
	require.Equal(t, exp, gotExp.Unix())

	gotIat, err := jtd.GetIssuedAt()
	require.NoError(t, err)
	require.Equal(t, iat, gotIat.Unix())
}

func TestJwtTokenData_RefreshLoop(t *testing.T) {
	jtd, dummyToken := setupRefreshLoopTest(t)
	reqCount := 0
	client := setupRefreshClient(t, &reqCount, dummyToken)

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		time.Sleep(300 * time.Millisecond)
		cancel()
	}()

	var buf bytes.Buffer

	err := jtd.RefreshLoop(
		ctx,
		"http://dummy.url",
		map[string]string{"client_id": "foo"},
		client,
		io.ReadAll,
		0.0, // trigger refresh immediately
		"",
		&buf,
	)
	require.NoError(t, err)

	require.NotZero(t, reqCount, "expected refresh request to be made")
	require.Equal(t, "new-refresh-token", jtd.RefreshTokenRaw)
}

func setupRefreshLoopTest(t *testing.T) (*JwtTokenData, string) {
	exp := time.Now().Add(5 * time.Second).Unix()
	iat := time.Now().Unix()
	claims := map[string]any{"exp": float64(exp), "iat": float64(iat)}

	claimsBytes, err := json.Marshal(claims)
	require.NoError(t, err)

	jtd := &JwtTokenData{
		AccessTokenClaims: claimsBytes,
		RefreshTokenRaw:   "initial-refresh-token",
	}

	header := `{"alg":"none"}`
	b64Header := base64.RawURLEncoding.EncodeToString([]byte(header))
	newExp := time.Now().Add(1 * time.Hour).Unix()
	newClaims := fmt.Sprintf(`{"exp":%d,"iat":%d}`, newExp, iat)
	b64Claims := base64.RawURLEncoding.EncodeToString([]byte(newClaims))
	dummyToken := fmt.Sprintf("%s.%s.", b64Header, b64Claims)

	return jtd, dummyToken
}

func setupRefreshClient(t *testing.T, reqCount *int, dummyToken string) *http.Client {
	return &http.Client{
		Transport: &mockTransport{
			roundTripFunc: func(req *http.Request) (*http.Response, error) {
				*reqCount++

				if err := req.ParseForm(); err != nil {
					t.Fatalf("ParseForm error: %v", err)
				}

				if req.Form.Get("grant_type") != "refresh_token" {
					t.Errorf("expected grant_type refresh_token, got %s", req.Form.Get("grant_type"))
				}

				currentRefreshToken := req.Form.Get("refresh_token")
				if currentRefreshToken == "" {
					require.NotEmpty(t, currentRefreshToken, "expected refresh_token to be provided")
				}

				respBody := fmt.Sprintf(`{"access_token": "%s", "refresh_token": "new-refresh-token"}`, dummyToken)

				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(respBody)),
					Header:     http.Header{"Content-Type": []string{"application/json"}},
				}, nil
			},
		},
	}
}

func TestJwtTokenData_WriteTokenToFile(t *testing.T) {
	jtd := &JwtTokenData{
		AccessTokenRaw: "initial-token",
	}

	tempFile, err := os.CreateTemp("", "token-test-*")
	require.NoError(t, err)
	tempFile.Close()

	defer os.Remove(tempFile.Name())

	var buf bytes.Buffer
	jtd.WriteTokenToFile(tempFile.Name(), &buf)

	data, err := os.ReadFile(tempFile.Name())
	require.NoError(t, err)
	require.Equal(t, "initial-token", string(data))
	require.Contains(t, buf.String(), "Token persisted to")
}

func TestJwtTokenData_TimingMethods_Errors(t *testing.T) {
	tests := []struct {
		name    string
		jtd     *JwtTokenData
		wantErr string
	}{
		{
			name:    "nil_claims",
			jtd:     &JwtTokenData{AccessTokenClaims: nil},
			wantErr: "access token claims are empty",
		},
		{
			name:    "invalid_json",
			jtd:     &JwtTokenData{AccessTokenClaims: []byte(`{invalid}`)},
			wantErr: "unable to unmarshal claims",
		},
		{
			name:    "missing_exp",
			jtd:     &JwtTokenData{AccessTokenClaims: []byte(`{"iat":123}`)},
			wantErr: "exp claim missing",
		},
		{
			name:    "non_numeric_exp",
			jtd:     &JwtTokenData{AccessTokenClaims: []byte(`{"exp":"not-a-number"}`)},
			wantErr: "exp claim is not a numeric timestamp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.jtd.GetExpiration()
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.wantErr)

			_, err = tt.jtd.GetIssuedAt()
			if tt.name == "nil_claims" || tt.name == "invalid_json" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

func TestJwtTokenData_RefreshLoop_ErrorRetry(t *testing.T) {
	// Create token that expires very soon to trigger refresh
	jtd := &JwtTokenData{
		AccessTokenRaw: "initial",
		AccessTokenClaims: []byte(fmt.Sprintf(`{"exp":%d, "iat":%d}`,
			time.Now().Add(100*time.Millisecond).Unix(),
			time.Now().Add(-1*time.Hour).Unix())),
	}

	// Mock client that fails
	client := &http.Client{
		Transport: &mockTransport{
			roundTripFunc: func(_ *http.Request) (*http.Response, error) {
				return nil, errors.New("network error")
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	var buf bytes.Buffer
	// This will try to refresh, fail, then wait for 10s or context cancel.
	// Since context is short, it should return nil when context expires.
	err := jtd.RefreshLoop(
		ctx,
		"http://dummy.url",
		map[string]string{"client_id": "foo"},
		client,
		io.ReadAll,
		1.0, // trigger immediately
		"",
		&buf,
	)
	require.NoError(t, err, "RefreshLoop should return nil on context cancel")
	require.Contains(t, buf.String(), "Failed to refresh token")
	require.Contains(t, buf.String(), "network error")
}

func TestJwtTokenData_CalculateWaitDuration_Validation(t *testing.T) {
	jtd := &JwtTokenData{}

	_, err := jtd.calculateWaitDuration(-1.0)
	require.Error(t, err)
	require.Contains(t, err.Error(), "renewThreshold must be between 0 and 100")

	_, err = jtd.calculateWaitDuration(101.0)
	require.Error(t, err)
	require.Contains(t, err.Error(), "renewThreshold must be between 0 and 100")
}
