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

type JwtTokenData struct {
	AccessTokenRaw     string `json:"access_token"` //nolint:tagliatelle // OAuth token field name
	AccessTokenJwt     *jwt.Token
	AccessTokenHeader  []byte
	AccessTokenClaims  []byte
	RefreshTokenRaw    string `json:"refresh_token"` //nolint:tagliatelle // OAuth token field name
	RefreshTokenJwt    *jwt.Token
	RefreshTokenHeader []byte
	RefreshTokenClaims []byte
}

type allReader func(io.Reader) ([]byte, error)

func RequestToken(reqURL string, reqValues map[string]string, client *http.Client, readAll allReader) (JwtTokenData, error) {
	if reqURL == emptyString {
		return JwtTokenData{}, errors.New("empty string provided as request URL")
	}

	if len(reqValues) == 0 {
		return JwtTokenData{}, errors.New("empty map provided as request values")
	}

	var t JwtTokenData

	urlReqValues := url.Values{}
	for k, v := range reqValues {
		urlReqValues.Add(k, v)
	}

	req, err := http.NewRequest(
		"POST",
		reqURL,
		strings.NewReader(urlReqValues.Encode()),
	)
	if err != nil {
		return JwtTokenData{}, fmt.Errorf(
			"HTTP error while defining token data request: %w",
			err,
		)
	}

	req.Header.Add("User-Agent", userAgent)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(urlReqValues.Encode())))

	resp, err := client.Do(req)
	if err != nil {
		return JwtTokenData{}, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return JwtTokenData{}, fmt.Errorf(
			"token request returned the following status code: %d",
			resp.StatusCode,
		)
	}

	bodyBytes, errBodyRead := readAll(resp.Body)
	resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	if errBodyRead != nil {
		return JwtTokenData{}, fmt.Errorf(
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
			return JwtTokenData{}, fmt.Errorf(
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
		return JwtTokenData{}, fmt.Errorf(
			"unable to parse JWT token from HTTP response: %w",
			err,
		)
	}

	return t, nil
}

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

	maps.Copy(reqValuesMap, objmap)

	return reqValuesMap, nil
}

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
		return nil, fmt.Errorf("unable to parse JSON from requests's values file: %w", err)
	}

	return returnValuesMap, nil
}

func isValidJSON(data []byte) bool {
	var v any
	return json.Unmarshal(data, &v) == nil
}

func (jtd *JwtTokenData) DecodeBase64() error {
	tokens := []struct {
		name string
		raw  string
	}{
		{
			name: "AccessToken",
			raw:  jtd.AccessTokenRaw,
		},
		{
			name: "RefreshToken",
			raw:  jtd.RefreshTokenRaw,
		},
	}

	for _, token := range tokens {
		if token.raw == emptyString {
			continue
		}

		var tokenHeader []byte

		var tokenClaims []byte

		var err error

		tokenB64Elements := strings.Split(token.raw, ".")
		if len(tokenB64Elements) != 3 {
			return fmt.Errorf("invalid three dotted JWT format in %s", token.name)
		}

		tokenHeader, err = base64.RawURLEncoding.DecodeString(tokenB64Elements[0])
		if err != nil {
			return fmt.Errorf(
				"unable to decode base64 header from %s: %w",
				token.name,
				err,
			)
		}

		if !isValidJSON(tokenHeader) {
			return fmt.Errorf(
				"invalid JSON found in header from %s: %w",
				token.name,
				err,
			)
		}

		tokenClaims, err = base64.RawURLEncoding.DecodeString(tokenB64Elements[1])
		if err != nil {
			return fmt.Errorf(
				"unable to decode base64 claims from %s: %w",
				token.name,
				err,
			)
		}

		if !isValidJSON(tokenClaims) {
			return fmt.Errorf(
				"invalid JSON found in claims from %s: %w",
				token.name,
				err,
			)
		}

		if token.name == "AccessToken" {
			jtd.AccessTokenHeader = tokenHeader
			jtd.AccessTokenClaims = tokenClaims
		}

		if token.name == "RefreshToken" {
			jtd.RefreshTokenHeader = tokenHeader
			jtd.RefreshTokenClaims = tokenClaims
		}
	}

	return nil
}

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

func (jtd *JwtTokenData) ParseWithJWKS(jwksURL string, keyfuncOverride keyfunc.Override) error {
	if jwksURL == emptyString {
		return errors.New("emptyString string provided as JWKS url")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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

func PrintTokenInfo(jtd JwtTokenData, w io.Writer) error {
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

		if token.name == "AccessToken" {
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

		tokenTimeClaims, err := unmarshallTokenTimeClaims(token.claims)
		if err != nil {
			return fmt.Errorf("unable to unmashall time claims from %s: %w", token.name, err)
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

func unmarshallTokenTimeClaims(claims []byte) (map[string]string, error) {
	tokenClaims := make(map[string]string)

	genericClaims := make(map[string]any)

	if err := json.Unmarshal(claims, &genericClaims); err != nil {
		return nil, fmt.Errorf("unable to unmarshall claims: %w", err)
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
		var vi any = v

		if vf, ok := vi.(float64); ok {
			vInt64 := int64(vf)
			t := time.Unix(vInt64, 0)
			dateUtc := t.UTC().Format(time.UnixDate)
			tokenClaims[k] = fmt.Sprintf("%v", dateUtc)

			continue
		}
	}

	return tokenClaims, nil
}

// func unmarshallTokenClaims(claims []byte) (map[string]string, error) {
// 	tokenClaims := make(map[string]string)
//
// 	genericClaims := make(map[string]any)
//
// 	if err := json.Unmarshal(claims, &genericClaims); err != nil {
// 		return nil, err
// 	}
//
// 	for k, v := range genericClaims {
// 		var vi any = v
//
// 		if vs, ok := vi.(map[string]any); ok {
// 			tokenClaims[k] = fmt.Sprintf("%s", vs)
// 			continue
// 		}
//
// 		if vf, ok := vi.(float64); ok {
// 			vInt64 := int64(vf)
// 			t := time.Unix(vInt64, 0)
// 			dateUtc := t.UTC().String()
//
// 			outString := fmt.Sprintf("%v (%s)", int64(vf), dateUtc)
//
// 			tokenClaims[k] = fmt.Sprintf("%v", outString)
//
// 			continue
// 		}
//
// 		if vls, ok := vi.([]string); ok {
// 			tokenClaims[k] = strings.Join(vls, ",")
// 			continue
// 		}
//
// 		if vla, ok := vi.([]any); ok {
// 			tokenClaims[k] = fmt.Sprintf("%v", vla)
// 			continue
// 		}
//
// 		if vb, ok := vi.(bool); ok {
// 			tokenClaims[k] = fmt.Sprintf("%v", vb)
// 			continue
// 		}
//
// 		if vs, ok := vi.(string); ok {
// 			tokenClaims[k] = vs
// 		} else {
// 			fmt.Printf("not asserted: %v\n", v)
// 		}
// 	}
//
// 	return tokenClaims, nil
// }
//
// func unmarshallTokenHeader(header []byte) (map[string]string, error) {
// 	tokenHeader := make(map[string]string)
//
// 	if err := json.Unmarshal(header, &tokenHeader); err != nil {
// 		return nil, err
// 	}
//
// 	return tokenHeader, nil
// }
//
// func getTokenClaimsMap(t *jwt.Token) (map[string]string, error) {
// 	m := make(map[string]string)
//
// 	// Mandatory Registered Claims
// 	issuer, err := t.Claims.GetIssuer()
// 	if err != nil || issuer == emptyString {
// 		return nil, fmt.Errorf("unable to get issuer: %w", err)
// 	}
//
// 	subject, err := t.Claims.GetSubject()
// 	if err != nil || subject == emptyString {
// 		return nil, fmt.Errorf("unable to get subject: %w", err)
// 	}
//
// 	issuedAt, err := t.Claims.GetIssuedAt()
// 	if err != nil || issuedAt == nil {
// 		return nil, fmt.Errorf("unable to get issuedAt: %w", err)
// 	}
//
// 	expiresAt, err := t.Claims.GetExpirationTime()
// 	if err != nil || expiresAt == nil {
// 		return nil, fmt.Errorf("unable to get expiration time: %w", err)
// 	}
//
// 	audienceElems, err := t.Claims.GetAudience()
// 	if err != nil {
// 		return nil, fmt.Errorf("unable to get audience: %w", err)
// 	}
//
// 	audience := strings.Join(audienceElems, ",")
//
// 	m["iss"] = issuer
// 	m["sub"] = subject
// 	m["iat"] = issuedAt.UTC().String()
// 	m["exp"] = expiresAt.UTC().String()
// 	m["aud"] = audience
//
// 	// Optional Registered Claims
// 	notBefore, err := t.Claims.GetNotBefore()
// 	if err != nil {
// 		return nil, fmt.Errorf("unable to get notBefore time: %w", err)
// 	}
//
// 	if notBefore != nil {
// 		m["nbf"] = notBefore.UTC().String()
// 	}
//
// 	return m, nil
// }
//
// func getUnregisteredClaimsMap(t *jwt.Token, existingClaims map[string]string) map[string]string {
// 	unregistreredClaims := make(map[string]string)
//
// 	var claimsInt any = t.Claims
//
// 	if claimsMap, ok := claimsInt.(jwt.MapClaims); ok {
// 		for ck := range claimsMap {
// 			if _, alreadyPresent := existingClaims[ck]; alreadyPresent {
// 				continue
// 			}
//
// 			cki := claimsMap[ck]
//
// 			if cStringValue, ok := cki.(string); ok {
// 				unregistreredClaims[ck] = cStringValue
// 			}
//
// 			if cIntList, ok := cki.([]any); ok {
// 				unregistreredClaims[ck] = fmt.Sprintf("%s", cIntList)
// 			}
// 		}
// 	}
//
// 	return unregistreredClaims
// }
//
// func getTokenHeadersMap(t *jwt.Token) map[string]string {
// 	m := make(map[string]string)
//
// 	for k, v := range t.Header {
// 		headerValue := "undefined"
// 		i := v
//
// 		if v, ok := i.(string); ok {
// 			headerValue = v
// 		}
//
// 		m[k] = headerValue
// 	}
//
// 	return m
// }
