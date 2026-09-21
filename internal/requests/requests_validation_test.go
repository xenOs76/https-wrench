package requests

import (
	"bytes"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xenos76/https-wrench/internal/view"
)

func TestImportResponseBody_FailRegexp(t *testing.T) {
	t.Run("matches fail regex", func(t *testing.T) {
		rd := &ResponseData{
			Request: RequestConfig{
				ResponseBodyFailRegexp: `(?i)error|fatal`,
			},
			Response: &http.Response{
				Body:   io.NopCloser(bytes.NewBufferString("Fatal database error")),
				Header: make(http.Header),
			},
		}

		rd.ImportResponseBody()
		assert.True(t, rd.ResponseBodyFailRegexpMatched)
	})

	t.Run("does not match fail regex", func(t *testing.T) {
		rd := &ResponseData{
			Request: RequestConfig{
				ResponseBodyFailRegexp: `(?i)error|fatal`,
			},
			Response: &http.Response{
				Body:   io.NopCloser(bytes.NewBufferString("All systems operational")),
				Header: make(http.Header),
			},
		}

		rd.ImportResponseBody()
		assert.False(t, rd.ResponseBodyFailRegexpMatched)
	})
}

func TestEvaluateResponseHeaders_Match(t *testing.T) {
	t.Run("header match regex all matched", func(t *testing.T) {
		headers := make(http.Header)
		headers.Set("Content-Type", "application/json; charset=utf-8")
		headers.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		rd := &ResponseData{
			Request: RequestConfig{
				ResponseHeaderMatchRegexp: map[string]string{
					"content-type":              `^application/json`,
					"Strict-Transport-Security": `max-age=\d+`,
				},
			},
			Response: &http.Response{Header: headers},
		}

		rd.EvaluateResponseHeaders()
		require.NotNil(t, rd.ResponseHeaderMatchRegexpMatched)
		assert.True(t, *rd.ResponseHeaderMatchRegexpMatched)
	})

	t.Run("header match regex missing header", func(t *testing.T) {
		headers := make(http.Header)
		headers.Set("Content-Type", "application/json")

		rd := &ResponseData{
			Request: RequestConfig{
				ResponseHeaderMatchRegexp: map[string]string{
					"X-Required-Token": `.+`,
				},
			},
			Response: &http.Response{Header: headers},
		}

		rd.EvaluateResponseHeaders()
		require.NotNil(t, rd.ResponseHeaderMatchRegexpMatched)
		assert.False(t, *rd.ResponseHeaderMatchRegexpMatched)
	})

	t.Run("header match regex mismatch value", func(t *testing.T) {
		headers := make(http.Header)
		headers.Set("Content-Type", "text/html")

		rd := &ResponseData{
			Request: RequestConfig{
				ResponseHeaderMatchRegexp: map[string]string{
					"Content-Type": `^application/json`,
				},
			},
			Response: &http.Response{Header: headers},
		}

		rd.EvaluateResponseHeaders()
		require.NotNil(t, rd.ResponseHeaderMatchRegexpMatched)
		assert.False(t, *rd.ResponseHeaderMatchRegexpMatched)
	})
}

func TestEvaluateResponseHeaders_Fail(t *testing.T) {
	t.Run("header fail regex matched (triggering failure)", func(t *testing.T) {
		headers := make(http.Header)
		headers.Set("Server", "Apache/2.4.41")

		rd := &ResponseData{
			Request: RequestConfig{
				ResponseHeaderFailRegexp: map[string]string{
					"Server": `(?i)apache`,
				},
			},
			Response: &http.Response{Header: headers},
		}

		rd.EvaluateResponseHeaders()
		require.NotNil(t, rd.ResponseHeaderFailRegexpMatched)
		assert.True(t, *rd.ResponseHeaderFailRegexpMatched)
	})

	t.Run("header fail regex not matched (passing)", func(t *testing.T) {
		headers := make(http.Header)
		headers.Set("Server", "nginx/1.18.0")

		rd := &ResponseData{
			Request: RequestConfig{
				ResponseHeaderFailRegexp: map[string]string{
					"Server": `(?i)apache`,
				},
			},
			Response: &http.Response{Header: headers},
		}

		rd.EvaluateResponseHeaders()
		require.NotNil(t, rd.ResponseHeaderFailRegexpMatched)
		assert.False(t, *rd.ResponseHeaderFailRegexpMatched)
	})

	t.Run("header fail regex missing header (passing)", func(t *testing.T) {
		headers := make(http.Header)

		rd := &ResponseData{
			Request: RequestConfig{
				ResponseHeaderFailRegexp: map[string]string{
					"Server": `(?i)apache`,
				},
			},
			Response: &http.Response{Header: headers},
		}

		rd.EvaluateResponseHeaders()
		require.NotNil(t, rd.ResponseHeaderFailRegexpMatched)
		assert.False(t, *rd.ResponseHeaderFailRegexpMatched)
	})
}

func TestBuildResponseResult_ValidationFields(t *testing.T) {
	trueVal := true
	falseVal := false
	rd := ResponseData{
		Request: RequestConfig{
			ValidStatusCodes:          []int{404, 410},
			ResponseBodyMatchRegexp:   "test",
			ResponseBodyFailRegexp:    "error",
			ResponseHeaderMatchRegexp: map[string]string{"Content-Type": "json"},
			ResponseHeaderFailRegexp:  map[string]string{"Server": "apache"},
		},
		Response: &http.Response{
			StatusCode: 404,
			Status:     "404 Not Found",
			Header:     make(http.Header),
		},
		ResponseBodyRegexpMatched:        true,
		ResponseBodyFailRegexpMatched:    false,
		ResponseHeaderMatchRegexpMatched: &trueVal,
		ResponseHeaderFailRegexpMatched:  &falseVal,
	}

	res := buildResponseResult(rd)
	assert.Equal(t, []int{404, 410}, res.ValidStatusCodes)
	require.NotNil(t, res.BodyRegexpMatched)
	assert.True(t, *res.BodyRegexpMatched)
	require.NotNil(t, res.BodyFailRegexpMatched)
	assert.False(t, *res.BodyFailRegexpMatched)
	require.NotNil(t, res.HeaderMatchRegexpMatched)
	assert.True(t, *res.HeaderMatchRegexpMatched)
	require.NotNil(t, res.HeaderFailRegexpMatched)
	assert.False(t, *res.HeaderFailRegexpMatched)
}

func TestViewStatusNodes_ValidStatusCodes(t *testing.T) {
	t.Run("expected 404 is toned as success", func(t *testing.T) {
		nodes := statusNodes(ResponseResult{
			StatusCode:       404,
			ValidStatusCodes: []int{404},
		})
		require.Len(t, nodes, 1)
		kv, ok := nodes[0].(view.KV)
		require.True(t, ok)
		assert.Equal(t, view.ToneStatus2xx, kv.Tone)
	})

	t.Run("unexpected 200 when only 404 expected is toned as error", func(t *testing.T) {
		nodes := statusNodes(ResponseResult{
			StatusCode:       200,
			ValidStatusCodes: []int{404},
		})
		require.Len(t, nodes, 1)
		kv, ok := nodes[0].(view.KV)
		require.True(t, ok)
		assert.Equal(t, view.ToneStatus5xx, kv.Tone)
	})
}
