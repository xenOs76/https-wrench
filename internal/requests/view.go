/*
Copyright © 2026 Zeno Belli xeno@os76.xyz
*/

package requests

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/xenos76/https-wrench/internal/certinfo"
	"github.com/xenos76/https-wrench/internal/view"
)

// DocOptions customizes view document rendering.
type DocOptions struct {
	WithoutBanner bool
}

// BuildDoc constructs a console view document from a Result.
func BuildDoc(r *Result) view.Doc {
	return BuildDocWithOptions(r, DocOptions{})
}

// BuildDocWithOptions constructs a console view document with custom options.
func BuildDocWithOptions(r *Result, opts DocOptions) view.Doc {
	nodes := make([]view.Node, 0, 8)
	if !opts.WithoutBanner {
		nodes = append(nodes,
			view.Blank{},
			view.Banner{Text: "Requests"},
			view.Blank{},
		)
	}

	if r == nil {
		return view.Doc{Nodes: nodes}
	}

	for _, req := range r.Requests {
		reqKids := make([]view.Node, 0, len(req.Responses)*4)

		if req.TransportOverrideURL != "" {
			reqKids = append(reqKids, view.KV{
				Key:   "Via",
				Value: req.TransportOverrideURL,
				Tone:  view.ToneURL,
			})
		}

		for _, resp := range req.Responses {
			reqKids = append(reqKids, responseNodes(resp)...)
		}

		nodes = append(nodes, view.Section{
			Title: fmt.Sprintf("Request: %s", req.Name),
			Level: 1,
			Kids:  reqKids,
		})
	}

	return view.Doc{Nodes: nodes}
}

// SingleResponseDoc builds a view document for a single response result.
func SingleResponseDoc(resp ResponseResult) view.Doc {
	return view.Doc{Nodes: responseNodes(resp)}
}

func responseNodes(resp ResponseResult) []view.Node {
	kids := make([]view.Node, 0, 8)

	kids = append(kids, view.KV{
		Key:   "- Url",
		Value: resp.URL,
		Tone:  view.ToneURL,
	})

	kids = append(kids, statusNodes(resp)...)

	if resp.TLS != nil {
		kids = append(kids, tlsSection(resp.TLS))
	}

	if len(resp.Headers) > 0 {
		kids = append(kids, headerSection(resp.Headers))
	}

	if node := bodyRegexpNode(resp); node != nil {
		kids = append(kids, node)
	}

	if node := bodyFailRegexpNode(resp); node != nil {
		kids = append(kids, node)
	}

	if node := headerMatchRegexpNode(resp); node != nil {
		kids = append(kids, node)
	}

	if node := headerFailRegexpNode(resp); node != nil {
		kids = append(kids, node)
	}

	if resp.Body != "" {
		kids = append(kids, view.Section{
			Title: "Body:",
			Level: 2,
			Kids: []view.Node{
				view.Code{
					Lang: resp.ContentType,
					Body: resp.Body,
				},
			},
		})
	}

	return kids
}

func resolveStatusTone(statusCode int, validCodes []int) view.Tone {
	if len(validCodes) > 0 {
		if slices.Contains(validCodes, statusCode) {
			return view.ToneStatus2xx
		}

		return view.ToneStatus5xx
	}

	switch {
	case statusCode >= 200 && statusCode < 300:
		return view.ToneStatus2xx
	case statusCode >= 300 && statusCode < 400:
		return view.ToneStatus3xx
	case statusCode >= 400 && statusCode < 500:
		return view.ToneStatus4xx
	default:
		return view.ToneStatus5xx
	}
}

func statusNodes(resp ResponseResult) []view.Node {
	if resp.Error != "" {
		return []view.Node{
			view.KV{Key: "StatusCode", Value: "0", Tone: view.ToneStatus5xx},
			view.KV{Key: "Error", Value: resp.Error, Tone: view.ToneCrit},
		}
	}

	statusStr := strconv.Itoa(resp.StatusCode)
	if resp.Status != "" {
		statusStr = resp.Status
	}

	return []view.Node{
		view.KV{
			Key:   "StatusCode",
			Value: statusStr,
			Tone:  resolveStatusTone(resp.StatusCode, resp.ValidStatusCodes),
		},
	}
}

func tlsSection(tlsInfo *ResponseTLSResult) view.Node {
	tlsKids := []view.Node{
		view.Table{
			Rows: [][]view.Cell{
				{{Text: "Version", Tone: view.ToneKey}, {Text: tlsInfo.Version, Tone: view.ToneValue}},
				{{Text: "CipherSuite", Tone: view.ToneKey}, {Text: tlsInfo.CipherSuite, Tone: view.ToneValue}},
				{{Text: "Key Exchange", Tone: view.ToneKey}, {Text: tlsInfo.KeyExchange, Tone: view.ToneValue}},
			},
		},
	}

	certDoc := certinfo.CertInfosDoc(tlsInfo.Certificates, tlsInfo.CertificatesFilter)
	tlsKids = append(tlsKids, certDoc.Nodes...)

	return view.Section{
		Title: "TLS:",
		Level: 2,
		Kids:  tlsKids,
	}
}

func headerSection(headers map[string][]string) view.Node {
	headerRows := make([][]view.Cell, 0, len(headers))
	keys := make([]string, 0, len(headers))

	for k := range headers {
		keys = append(keys, k)
	}

	slices.Sort(keys)

	for _, k := range keys {
		vals := strings.Join(headers[k], ", ")
		headerRows = append(headerRows, []view.Cell{
			{Text: k, Tone: view.ToneKey},
			{Text: vals, Tone: view.ToneValue},
		})
	}

	return view.Section{
		Title: "Headers:",
		Level: 2,
		Kids:  []view.Node{view.Table{Rows: headerRows}},
	}
}

func bodyRegexpNode(resp ResponseResult) view.Node {
	if resp.BodyRegexpMatched == nil {
		return nil
	}

	matchTone := view.ToneBoolFalse
	matchVal := "false"

	if *resp.BodyRegexpMatched {
		matchTone = view.ToneBoolTrue
		matchVal = "true"
	}

	return view.KV{
		Key:   "BodyRegexpMatch",
		Value: matchVal,
		Tone:  matchTone,
	}
}

func bodyFailRegexpNode(resp ResponseResult) view.Node {
	if resp.BodyFailRegexpMatched == nil {
		return nil
	}

	matchTone := view.ToneBoolTrue
	matchVal := "false"

	if *resp.BodyFailRegexpMatched {
		matchTone = view.ToneCrit
		matchVal = "true"
	}

	return view.KV{
		Key:   "BodyFailRegexpMatch",
		Value: matchVal,
		Tone:  matchTone,
	}
}

func headerMatchRegexpNode(resp ResponseResult) view.Node {
	if resp.HeaderMatchRegexpMatched == nil {
		return nil
	}

	matchTone := view.ToneCrit
	matchVal := "false"

	if *resp.HeaderMatchRegexpMatched {
		matchTone = view.ToneBoolTrue
		matchVal = "true"
	}

	return view.KV{
		Key:   "HeaderMatchRegexp",
		Value: matchVal,
		Tone:  matchTone,
	}
}

func headerFailRegexpNode(resp ResponseResult) view.Node {
	if resp.HeaderFailRegexpMatched == nil {
		return nil
	}

	matchTone := view.ToneBoolTrue
	matchVal := "false"

	if *resp.HeaderFailRegexpMatched {
		matchTone = view.ToneCrit
		matchVal = "true"
	}

	return view.KV{
		Key:   "HeaderFailRegexp",
		Value: matchVal,
		Tone:  matchTone,
	}
}
