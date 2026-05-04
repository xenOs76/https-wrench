package jwtinfo

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/charmbracelet/lipgloss/table"
	"github.com/golang-jwt/jwt/v5"
	"github.com/xenos76/https-wrench/internal/style"
)

var (
	chromaStyle = "catppuccin-frappe"
	emptyString string
	userAgent   = "HTTPS-Wrench/JwtInfo"
)

// JwtTokenData holds the raw and parsed data for access and refresh tokens.
type JwtTokenData struct {
	// AccessTokenRaw is the raw base64-encoded access token string.
	AccessTokenRaw string `json:"access_token"` //nolint:tagliatelle // OAuth token field name
	// AccessTokenJwt is the parsed access token object.
	AccessTokenJwt *jwt.Token
	// AccessTokenHeader is the decoded JSON header of the access token.
	AccessTokenHeader []byte
	// AccessTokenClaims is the decoded JSON claims of the access token.
	AccessTokenClaims []byte
	// RefreshTokenRaw is the raw base64-encoded refresh token string.
	RefreshTokenRaw string `json:"refresh_token"` //nolint:tagliatelle // OAuth token field name
	// RefreshTokenJwt is the parsed refresh token object.
	RefreshTokenJwt *jwt.Token
	// RefreshTokenHeader is the decoded JSON header of the refresh token.
	RefreshTokenHeader []byte
	// RefreshTokenClaims is the decoded JSON claims of the refresh token.
	RefreshTokenClaims []byte
}

// AllReader is a function type that reads all data from an io.Reader.
type AllReader func(io.Reader) ([]byte, error)

// RequestToken makes an HTTP POST request to the given URL with the provided values
// to retrieve a JWT token. It handles both application/jwt and application/json
// response types.
//
//nolint:revive
func RequestToken(ctx context.Context, reqURL string, reqValues map[string]string, client *http.Client, readAll AllReader) (*JwtTokenData, error) {
	if readAll == nil {
		return nil, errors.New("nil body reader function")
	}

	if reqURL == emptyString {
		return nil, errors.New("empty string provided as request URL")
	}

	if len(reqValues) == 0 {
		return nil, errors.New("empty map provided as request values")
	}

	t := &JwtTokenData{}

	urlReqValues := url.Values{}
	for k, v := range reqValues {
		urlReqValues.Add(k, v)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		"POST",
		reqURL,
		strings.NewReader(urlReqValues.Encode()),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"HTTP error while defining token data request: %w",
			err,
		)
	}

	req.Header.Add("User-Agent", userAgent)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(urlReqValues.Encode())))

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"token request returned the following status code: %d",
			resp.StatusCode,
		)
	}

	bodyBytes, errBodyRead := readAll(resp.Body)
	resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	if errBodyRead != nil {
		return nil, fmt.Errorf(
			"unable to read body: %w",
			errBodyRead,
		)
	}

	mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if mediaType == "application/jwt" {
		t.AccessTokenRaw = string(bodyBytes)
	}

	if mediaType == "application/json" {
		if err = json.NewDecoder(resp.Body).Decode(&t); err != nil {
			return nil, fmt.Errorf(
				"error validating token request data: %w",
				err,
			)
		}
	}

	_, _, err = jwt.NewParser().ParseUnverified(
		t.AccessTokenRaw,
		&jwt.RegisteredClaims{},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"unable to parse JWT token from HTTP response: %w",
			err,
		)
	}

	return t, nil
}

// ReadTokenFromFile reads a JWT token string from the specified file.
// It returns a JwtTokenData struct containing the raw token string.
func ReadTokenFromFile(fileName string) (*JwtTokenData, error) {
	data, err := os.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("unable to read token file: %w", err)
	}

	td := &JwtTokenData{AccessTokenRaw: strings.TrimSpace(string(data))}

	_, _, err = jwt.NewParser().ParseUnverified(
		td.AccessTokenRaw,
		&jwt.RegisteredClaims{},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"unable to parse JWT token from file: %w",
			err,
		)
	}

	return td, nil
}

// ParseRequestJSONValues parses a JSON-encoded string of request values and merges
// them into the provided map.
func ParseRequestJSONValues(
	reqValues string,
	reqValuesMap map[string]string,
) (
	map[string]string,
	error,
) {
	if reqValues == "" {
		return nil, errors.New("empty string provided as JSON encoded request values")
	}

	var objmap map[string]string

	err := json.Unmarshal([]byte(reqValues), &objmap)
	if err != nil {
		return nil, fmt.Errorf("unable to parse Json request values: %w", err)
	}

	newMap := maps.Clone(reqValuesMap)
	if newMap == nil {
		newMap = make(map[string]string)
	}

	maps.Copy(newMap, objmap)

	return newMap, nil
}

// ReadRequestValuesFile reads request values from a JSON file and merges them
// into the provided map.
func ReadRequestValuesFile(
	fileName string,
	reqValuesMap map[string]string,
) (
	map[string]string,
	error,
) {
	data, err := os.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("unable to read request's values file: %w", err)
	}

	returnValuesMap, err := ParseRequestJSONValues(string(data), reqValuesMap)
	if err != nil {
		return nil, fmt.Errorf("unable to parse JSON from request's values file: %w", err)
	}

	return returnValuesMap, nil
}

// isValidJSON checks if the provided byte slice contains valid JSON object data.
func isValidJSON(data []byte) bool {
	if !json.Valid(data) {
		return false
	}

	trimmed := bytes.TrimSpace(data)
	if len(trimmed) < 2 {
		return false
	}

	return trimmed[0] == '{' && trimmed[len(trimmed)-1] == '}'
}

// DecodeBase64 decodes the base64-encoded header and claims of the access and
// refresh tokens stored in the JwtTokenData struct.
func (jtd *JwtTokenData) DecodeBase64() error {
	if jtd.AccessTokenRaw != emptyString {
		header, claims, err := decodeToken("AccessToken", jtd.AccessTokenRaw)
		if err != nil {
			return err
		}

		jtd.AccessTokenHeader = header
		jtd.AccessTokenClaims = claims
	}

	if jtd.RefreshTokenRaw != emptyString {
		// A refresh token is not strictly required to be a JWT in OAuth2.
		// If it has 3 parts, we attempt to decode it as a JWT.
		// If it doesn't, we treat it as an opaque token and continue.
		if strings.Count(jtd.RefreshTokenRaw, ".") == 2 {
			header, claims, err := decodeToken("RefreshToken", jtd.RefreshTokenRaw)
			if err != nil {
				return err
			}

			jtd.RefreshTokenHeader = header
			jtd.RefreshTokenClaims = claims
		}
	}

	return nil
}

// decodeToken decodes and validates a single JWT token string (header and claims).
func decodeToken(name, raw string) (header []byte, claims []byte, err error) {
	tokenB64Elements := strings.Split(raw, ".")
	if len(tokenB64Elements) != 3 {
		return nil, nil, fmt.Errorf("invalid three dotted JWT format in %s", name)
	}

	header, err = base64.RawURLEncoding.DecodeString(tokenB64Elements[0])
	if err != nil {
		return nil, nil, fmt.Errorf("unable to decode base64 header from %s: %w", name, err)
	}

	if !isValidJSON(header) {
		return nil, nil, fmt.Errorf("invalid JSON found in header from %s", name)
	}

	claims, err = base64.RawURLEncoding.DecodeString(tokenB64Elements[1])
	if err != nil {
		return nil, nil, fmt.Errorf("unable to decode base64 claims from %s: %w", name, err)
	}

	if !isValidJSON(claims) {
		return nil, nil, fmt.Errorf("invalid JSON found in claims from %s", name)
	}

	return header, claims, nil
}

// ParseUnverified parses the access token without verifying its signature.
func (jtd *JwtTokenData) ParseUnverified() error {
	token, _, err := jwt.NewParser().ParseUnverified(
		jtd.AccessTokenRaw,
		&jwt.RegisteredClaims{},
	)
	if err != nil {
		return fmt.Errorf(
			"unable to parse AccessTokenRaw: %w",
			err,
		)
	}

	jtd.AccessTokenJwt = token

	return nil
}

// ParseWithJWKS parses and verifies the access token against the JSON Web Key Set (JWKS)
// provided at the given URL.
func (jtd *JwtTokenData) ParseWithJWKS(ctx context.Context, jwksURL string, keyfuncOverride keyfunc.Override) error {
	if jwksURL == emptyString {
		return errors.New("emptyString string provided as JWKS url")
	}

	jwks, err := keyfunc.NewDefaultOverrideCtx(
		ctx,
		[]string{jwksURL},
		keyfuncOverride,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to create JWK Set from resource at URL %s: %w",
			jwksURL,
			err,
		)
	}

	token, err := jwt.Parse(
		jtd.AccessTokenRaw,
		jwks.Keyfunc,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to parse the JWT AccessTokenRaw against JWKS Url %s: %w",
			jwksURL,
			err,
		)
	}

	jtd.AccessTokenJwt = token

	return nil
}

// PrintTokenInfo prints the decoded JWT token information (headers and claims)
// to the provided writer in a human-readable format.
//
//nolint:revive
func PrintTokenInfo(jtd *JwtTokenData, w io.Writer) error {
	sl := style.CertKeyP4.Render
	sv := style.CertValue.Render
	sTrue := style.BoolTrue.Render
	sFalse := style.BoolFalse.Render

	fmt.Fprintln(w)
	fmt.Fprintln(w, style.LgSprintf(style.Cmd, "JwtInfo"))
	fmt.Fprintln(w)

	validString := sFalse("false")
	if jtd.AccessTokenJwt != nil && jtd.AccessTokenJwt.Valid {
		validString = sTrue("true")
	}

	tokens := []struct {
		name   string
		header []byte
		claims []byte
	}{
		{
			name:   "AccessToken",
			header: jtd.AccessTokenHeader,
			claims: jtd.AccessTokenClaims,
		},
		{
			name:   "RefreshToken",
			header: jtd.RefreshTokenHeader,
			claims: jtd.RefreshTokenClaims,
		},
	}

	for _, token := range tokens {
		if len(token.header) == 0 {
			continue
		}

		fmt.Fprintln(w, style.LgSprintf(style.Title2, "%s", token.name))
		fmt.Fprintln(w)

		if token.name == "AccessToken" && jtd.AccessTokenJwt != nil {
			fmt.Fprintln(w, style.LgSprintf(style.ItemKey, "Valid %s", validString))
			fmt.Fprintln(w)
		}

		fmt.Fprintln(w, style.LgSprintf(style.ItemKey, "Header"))

		var prettyJSON bytes.Buffer

		err := json.Indent(&prettyJSON, token.header, "", "  ")
		if err != nil {
			prettyJSON.Write(token.header)
		}

		headerCode := prettyJSON.String()

		fmt.Fprint(w, style.CodeSyntaxHighlightWithStyle("json", headerCode, chromaStyle))
		prettyJSON.Reset()

		fmt.Fprintln(w)
		fmt.Fprintln(w, style.LgSprintf(style.ItemKey, "Claims"))

		tokenTimeClaims, err := unmarshalTokenTimeClaims(token.claims)
		if err != nil {
			return fmt.Errorf("unable to unmarshal time claims from %s: %w", token.name, err)
		}

		cTable := table.New().Border(style.LGDefBorder)
		cTable.Row(sl("Issued At"), sv(tokenTimeClaims["iat"]))
		cTable.Row(sl("Expiration Time"), sv(tokenTimeClaims["exp"]))
		fmt.Fprintln(w, cTable.Render())
		cTable.ClearRows()

		err = json.Indent(&prettyJSON, token.claims, "", "  ")
		if err != nil {
			prettyJSON.Write(token.claims)
		}

		claimsCode := prettyJSON.String()

		fmt.Fprint(w, style.CodeSyntaxHighlightWithStyle("json", claimsCode, chromaStyle))
		fmt.Fprintln(w)
	}

	return nil
}

// unmarshalTokenTimeClaims extracts and converts numeric "iat" and "exp" claims
// from a JSON byte slice into human-readable date strings.
func unmarshalTokenTimeClaims(claims []byte) (map[string]string, error) {
	tokenClaims := make(map[string]string)

	genericClaims := make(map[string]any)

	if err := json.Unmarshal(claims, &genericClaims); err != nil {
		return nil, fmt.Errorf("unable to unmarshal claims: %w", err)
	}

	if _, ok := genericClaims["iat"]; !ok {
		return nil, errors.New("unable to find Issued At (iat) in token Claims")
	}

	if _, ok := genericClaims["iat"].(float64); !ok {
		return nil, errors.New("Issued At (iat) claim is not a numeric timestamp")
	}

	if _, ok := genericClaims["exp"]; !ok {
		return nil, errors.New("unable to find Expiration Time (exp) in token Claims")
	}

	if _, ok := genericClaims["exp"].(float64); !ok {
		return nil, errors.New("Expiration Time (exp) claim is not a numeric timestamp")
	}

	for k, v := range genericClaims {
		if k == "iat" || k == "exp" || k == "nbf" {
			if vf, ok := v.(float64); ok {
				vInt64 := int64(vf)
				t := time.Unix(vInt64, 0)
				dateUTC := t.UTC().Format(time.UnixDate)
				tokenClaims[k] = dateUTC
			}
		}
	}

	return tokenClaims, nil
}

// GetExpiration extracts the expiration time (exp) from the token claims.
func (jtd *JwtTokenData) GetExpiration() (time.Time, error) {
	if jtd.AccessTokenClaims == nil {
		return time.Time{}, errors.New("access token claims are empty")
	}

	var genericClaims map[string]any
	if err := json.Unmarshal(jtd.AccessTokenClaims, &genericClaims); err != nil {
		return time.Time{}, fmt.Errorf("unable to unmarshal claims: %w", err)
	}

	if v, ok := genericClaims["exp"]; ok {
		if vf, ok := v.(float64); ok {
			return time.Unix(int64(vf), 0), nil
		}

		return time.Time{}, errors.New("exp claim is not a numeric timestamp")
	}

	return time.Time{}, errors.New("exp claim missing")
}

// GetIssuedAt extracts the issued at time (iat) from the token claims.
func (jtd *JwtTokenData) GetIssuedAt() (time.Time, error) {
	if jtd.AccessTokenClaims == nil {
		return time.Time{}, errors.New("access token claims are empty")
	}

	var genericClaims map[string]any
	if err := json.Unmarshal(jtd.AccessTokenClaims, &genericClaims); err != nil {
		return time.Time{}, fmt.Errorf("unable to unmarshal claims: %w", err)
	}

	if v, ok := genericClaims["iat"]; ok {
		if vf, ok := v.(float64); ok {
			return time.Unix(int64(vf), 0), nil
		}

		return time.Time{}, errors.New("iat claim is not a numeric timestamp")
	}

	return time.Time{}, errors.New("iat claim missing")
}

// Refresh attempts to acquire a new token either by using the refresh token or the original request values.
func (jtd *JwtTokenData) Refresh(
	ctx context.Context,
	reqURL string,
	reqValues map[string]string,
	client *http.Client,
	readAll AllReader,
) error {
	refreshValues := maps.Clone(reqValues)
	if refreshValues == nil {
		refreshValues = make(map[string]string)
	}

	if jtd.RefreshTokenRaw != "" {
		refreshValues["grant_type"] = "refresh_token"
		refreshValues["refresh_token"] = jtd.RefreshTokenRaw
	}

	newTokenData, err := RequestToken(ctx, reqURL, refreshValues, client, readAll)
	if err != nil {
		return fmt.Errorf("failed to request refreshed token: %w", err)
	}

	if err := newTokenData.DecodeBase64(); err != nil {
		return fmt.Errorf("failed to decode refreshed token: %w", err)
	}

	jtd.AccessTokenRaw = newTokenData.AccessTokenRaw
	jtd.AccessTokenJwt = newTokenData.AccessTokenJwt
	jtd.AccessTokenHeader = newTokenData.AccessTokenHeader
	jtd.AccessTokenClaims = newTokenData.AccessTokenClaims

	if newTokenData.RefreshTokenRaw != "" {
		jtd.RefreshTokenRaw = newTokenData.RefreshTokenRaw
		jtd.RefreshTokenJwt = newTokenData.RefreshTokenJwt
		jtd.RefreshTokenHeader = newTokenData.RefreshTokenHeader
		jtd.RefreshTokenClaims = newTokenData.RefreshTokenClaims
	}

	return nil
}

// RefreshLoop runs a loop that periodically refreshes the JWT token before it
// expires.
func (jtd *JwtTokenData) RefreshLoop(
	ctx context.Context,
	reqURL string,
	reqValues map[string]string,
	client *http.Client,
	readAll AllReader,
	renewThreshold float64,
	outFileName string,
	outWriter io.Writer,
) error {
	for {
		sleepFor, err := jtd.calculateWaitDuration(renewThreshold)
		if err != nil {
			return err
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(sleepFor):
		}

		if err := jtd.Refresh(ctx, reqURL, reqValues, client, readAll); err != nil {
			fmt.Fprintf(outWriter, "Failed to refresh token: %v\n", err)
			// Sleep before retrying on failure
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(10 * time.Second):
			}

			continue
		}

		jtd.WriteTokenToFile(outFileName, outWriter)
	}
}

// calculateWaitDuration determines how long to wait before the next token refresh
// based on the expiration time and the renewal threshold.
func (jtd *JwtTokenData) calculateWaitDuration(renewThreshold float64) (time.Duration, error) {
	if renewThreshold < 0 || renewThreshold > 100 {
		return 0, fmt.Errorf("renewThreshold must be between 0 and 100, got %.2f", renewThreshold)
	}

	exp, err := jtd.GetExpiration()
	if err != nil {
		return 0, fmt.Errorf("unable to determine expiration: %w", err)
	}

	iat, err := jtd.GetIssuedAt()

	var lifetime time.Duration

	var wakeTime time.Time

	if err == nil {
		lifetime = exp.Sub(iat)
		waitDuration := time.Duration(float64(lifetime) * (renewThreshold / 100.0))
		wakeTime = iat.Add(waitDuration)
	} else {
		// Fallback if iat is missing, use current time
		lifetime = time.Until(exp)
		waitDuration := time.Duration(float64(lifetime) * (renewThreshold / 100.0))
		wakeTime = time.Now().Add(waitDuration)
	}

	if lifetime <= 0 {
		return 0, errors.New("token lifetime is zero or negative")
	}

	sleepFor := time.Until(wakeTime)
	if sleepFor <= 0 {
		// If we are already past the wake time, trigger a refresh immediately.
		// But avoid a tight spin loop if refresh fails instantly.
		sleepFor = 100 * time.Millisecond
	}

	return sleepFor, nil
}

// WriteTokenToFile handles the persistence or display of a newly
// acquired token, either writing it to a file or printing it to the console.
func (jtd *JwtTokenData) WriteTokenToFile(outFileName string, outWriter io.Writer) {
	if outFileName == "" {
		fmt.Fprintf(outWriter, "\n--- Token Refreshed at %s ---\n", time.Now().Format(time.RFC3339))
		_ = PrintTokenInfo(jtd, outWriter)

		return
	}

	dir := filepath.Dir(outFileName)

	tmp, err := os.CreateTemp(dir, ".token-*")
	if err != nil {
		fmt.Fprintf(outWriter, "Failed to create temp token file for %s: %v\n", outFileName, err)
		return
	}

	tmpName := tmp.Name()

	if _, err := tmp.WriteString(jtd.AccessTokenRaw); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)

		fmt.Fprintf(outWriter, "Failed to write token to temp file for %s: %v\n", outFileName, err)

		return
	}

	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)

		fmt.Fprintf(outWriter, "Failed to close temp token file for %s: %v\n", outFileName, err)

		return
	}

	if err := os.Chmod(tmpName, 0o600); err != nil {
		_ = os.Remove(tmpName)

		fmt.Fprintf(outWriter, "Failed to set token file permissions for %s: %v\n", outFileName, err)

		return
	}

	if err := os.Rename(tmpName, outFileName); err != nil {
		_ = os.Remove(tmpName)

		fmt.Fprintf(outWriter, "Failed to replace token file %s: %v\n", outFileName, err)

		return
	}

	ts := time.Now().Format(time.RFC3339)
	fmt.Fprintf(outWriter, "[%s] Token persisted to %s\n", ts, outFileName)
}

// ParseKVValue parses a string in the format "key=value" and adds it to the provided map.
// It returns an error if the format is invalid or the string is empty.
func ParseKVValue(
	kv string,
	reqValuesMap map[string]string,
) (
	map[string]string,
	error,
) {
	if kv == "" {
		return nil, errors.New("empty string provided as key-value pair")
	}

	parts := strings.SplitN(kv, "=", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid key-value pair: %s (expected key=value)", kv)
	}

	key := strings.TrimSpace(parts[0])
	if key == "" {
		return nil, fmt.Errorf("empty request parameter name in: %s", kv)
	}

	newMap := maps.Clone(reqValuesMap)
	if newMap == nil {
		newMap = make(map[string]string)
	}

	newMap[key] = parts[1]

	return newMap, nil
}
