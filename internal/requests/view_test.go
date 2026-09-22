package requests

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xenos76/https-wrench/internal/view"
)

func TestRequests_ViewRendering(t *testing.T) {
	t.Parallel()

	trueVal := true
	falseVal := false

	res := ResponseResult{
		URL:                      "https://example.com/test",
		StatusCode:               200,
		Status:                   "200 OK",
		DurationMs:               12.5,
		BodyRegexpMatched:        &trueVal,
		BodyFailRegexpMatched:    &falseVal,
		HeaderMatchRegexpMatched: &trueVal,
		HeaderFailRegexpMatched:  &falseVal,
		TLS: &ResponseTLSResult{
			Version:     "TLS 1.3",
			CipherSuite: "TLS_AES_128_GCM_SHA256",
		},
		Headers: map[string][]string{
			"Content-Type": {"application/json"},
		},
		Body:        `{"status":"ok"}`,
		ContentType: "json",
	}

	// Test SingleResponseDoc
	singleDoc := SingleResponseDoc(res)
	require.NotEmpty(t, singleDoc.Nodes)

	// Test BuildDoc
	docResult := &Result{
		Requests: []RequestResult{
			{
				Name:                 "sample-req",
				TransportOverrideURL: "https://override.example.com",
				Responses: []ResponseResult{
					res,
				},
			},
		},
	}

	doc := BuildDoc(docResult)
	require.NotEmpty(t, doc.Nodes)

	docCustom := BuildDocWithOptions(docResult, DocOptions{WithoutBanner: true})
	require.NotEmpty(t, docCustom.Nodes)

	// Nil result doc
	docNil := BuildDoc(nil)
	require.NotEmpty(t, docNil.Nodes)
}

func TestRequests_RegexNodesBranches(t *testing.T) {
	t.Parallel()

	trueVal := true
	falseVal := false

	// Test with true matches
	resTrue := ResponseResult{
		BodyFailRegexpMatched:    &trueVal,
		HeaderMatchRegexpMatched: &trueVal,
		HeaderFailRegexpMatched:  &trueVal,
	}

	bfNode := bodyFailRegexpNode(resTrue)
	require.NotNil(t, bfNode)
	require.Equal(t, view.ToneCrit, bfNode.(view.KV).Tone)

	hmNode := headerMatchRegexpNode(resTrue)
	require.NotNil(t, hmNode)
	require.Equal(t, view.ToneBoolTrue, hmNode.(view.KV).Tone)

	hfNode := headerFailRegexpNode(resTrue)
	require.NotNil(t, hfNode)
	require.Equal(t, view.ToneCrit, hfNode.(view.KV).Tone)

	// Test with false matches
	resFalse := ResponseResult{
		BodyFailRegexpMatched:    &falseVal,
		HeaderMatchRegexpMatched: &falseVal,
		HeaderFailRegexpMatched:  &falseVal,
	}

	bfNodeFalse := bodyFailRegexpNode(resFalse)
	require.NotNil(t, bfNodeFalse)
	require.Equal(t, view.ToneBoolTrue, bfNodeFalse.(view.KV).Tone)

	hmNodeFalse := headerMatchRegexpNode(resFalse)
	require.NotNil(t, hmNodeFalse)
	require.Equal(t, view.ToneCrit, hmNodeFalse.(view.KV).Tone)

	hfNodeFalse := headerFailRegexpNode(resFalse)
	require.NotNil(t, hfNodeFalse)
	require.Equal(t, view.ToneBoolTrue, hfNodeFalse.(view.KV).Tone)

	// Test with nil
	resNil := ResponseResult{}
	require.Nil(t, bodyFailRegexpNode(resNil))
	require.Nil(t, headerMatchRegexpNode(resNil))
	require.Nil(t, headerFailRegexpNode(resNil))
}

func TestRequests_ResolveStatusTone(t *testing.T) {
	t.Parallel()

	// Status code tones without explicit validCodes
	require.Equal(t, view.ToneStatus2xx, resolveStatusTone(200, nil))
	require.Equal(t, view.ToneStatus3xx, resolveStatusTone(301, nil))
	require.Equal(t, view.ToneStatus4xx, resolveStatusTone(404, nil))
	require.Equal(t, view.ToneStatus5xx, resolveStatusTone(500, nil))
	require.Equal(t, view.ToneStatus5xx, resolveStatusTone(0, nil))

	// Status code tones with explicit validCodes
	valid := []int{200, 204}
	require.Equal(t, view.ToneStatus2xx, resolveStatusTone(200, valid))
	require.Equal(t, view.ToneStatus5xx, resolveStatusTone(201, valid))
}
