package executor

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/thinking"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/util"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v6/sdk/translator"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

const (
	toCodexDefaultChatPath             = "/v1/chat/completions"
	toCodexDefaultResponsesPath        = "/v1/responses"
	toCodexDefaultResponsesCompactPath = "/v1/responses/compact"
	toCodexFixedTitle                  = "ToCodex"
	toCodexFixedReferer                = "https://github.com/tocodex/ToCodex"
	toCodexFixedUserAgent              = "ToCodex/3.1.3"
)

type toCodexResolvedConfig struct {
	APIKey               string
	HMACSecret           string
	BaseURL              string
	RequestMode          string
	ChatPath             string
	ResponsesPath        string
	ResponsesCompactPath string
}

// ToCodexExecutor keeps the Codex translation path but signs upstream requests
// with the ToCodex-specific HMAC headers.
type ToCodexExecutor struct {
	*CodexExecutor
}

func NewToCodexExecutor(cfg *config.Config) *ToCodexExecutor {
	return &ToCodexExecutor{CodexExecutor: NewCodexExecutor(cfg)}
}

func (e *ToCodexExecutor) Identifier() string { return "tocodex" }

func (e *ToCodexExecutor) PrepareRequest(req *http.Request, auth *cliproxyauth.Auth) error {
	if req == nil {
		return nil
	}
	resolved, err := e.resolveRequestConfig(auth)
	if err != nil {
		return err
	}
	return applyToCodexHeaders(req, auth, resolved, nil, false)
}

func (e *ToCodexExecutor) HttpRequest(ctx context.Context, auth *cliproxyauth.Auth, req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, fmt.Errorf("tocodex executor: request is nil")
	}
	if ctx == nil {
		ctx = req.Context()
	}
	httpReq := req.WithContext(ctx)
	if err := e.PrepareRequest(httpReq, auth); err != nil {
		return nil, err
	}
	httpClient := helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0)
	return httpClient.Do(httpReq)
}

func (e *ToCodexExecutor) Execute(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (resp cliproxyexecutor.Response, err error) {
	resolved, err := e.resolveRequestConfig(auth)
	if err != nil {
		return resp, err
	}
	if resolved.RequestMode == "chat" {
		if opts.Alt == "responses/compact" {
			return resp, statusErr{code: http.StatusBadRequest, msg: "ToCodex chat mode does not support /responses/compact"}
		}
		return e.executeChat(ctx, auth, req, opts, resolved)
	}
	if opts.Alt == "responses/compact" {
		return e.executeResponsesCompact(ctx, auth, req, opts, resolved)
	}
	return e.executeResponses(ctx, auth, req, opts, resolved)
}

func (e *ToCodexExecutor) ExecuteStream(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (_ *cliproxyexecutor.StreamResult, err error) {
	resolved, err := e.resolveRequestConfig(auth)
	if err != nil {
		return nil, err
	}
	if resolved.RequestMode == "chat" {
		if opts.Alt == "responses/compact" {
			return nil, statusErr{code: http.StatusBadRequest, msg: "ToCodex chat mode does not support /responses/compact"}
		}
		return e.executeChatStream(ctx, auth, req, opts, resolved)
	}
	if opts.Alt == "responses/compact" {
		return nil, statusErr{code: http.StatusBadRequest, msg: "streaming not supported for /responses/compact"}
	}
	return e.executeResponsesStream(ctx, auth, req, opts, resolved)
}

func (e *ToCodexExecutor) CountTokens(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	resolved, err := e.resolveRequestConfig(auth)
	if err != nil {
		return cliproxyexecutor.Response{}, err
	}
	baseModel := thinking.ParseSuffix(req.Model).ModelName
	from := opts.SourceFormat

	if resolved.RequestMode == "chat" {
		to := sdktranslator.FormatOpenAI
		translated := sdktranslator.TranslateRequest(from, to, baseModel, req.Payload, false)
		translated, err = thinking.ApplyThinking(translated, req.Model, from.String(), to.String(), e.Identifier())
		if err != nil {
			return cliproxyexecutor.Response{}, err
		}
		enc, err := helps.TokenizerForModel(baseModel)
		if err != nil {
			return cliproxyexecutor.Response{}, fmt.Errorf("tocodex executor: tokenizer init failed: %w", err)
		}
		count, err := helps.CountOpenAIChatTokens(enc, translated)
		if err != nil {
			return cliproxyexecutor.Response{}, fmt.Errorf("tocodex executor: token counting failed: %w", err)
		}
		usageJSON := helps.BuildOpenAIUsageJSON(count)
		return cliproxyexecutor.Response{
			Payload: sdktranslator.TranslateTokenCount(ctx, to, from, count, usageJSON),
		}, nil
	}

	to := sdktranslator.FormatCodex
	body := sdktranslator.TranslateRequest(from, to, baseModel, req.Payload, false)
	body, err = thinking.ApplyThinking(body, req.Model, from.String(), to.String(), e.Identifier())
	if err != nil {
		return cliproxyexecutor.Response{}, err
	}
	body, _ = sjson.SetBytes(body, "model", baseModel)
	body, _ = sjson.DeleteBytes(body, "previous_response_id")
	body, _ = sjson.DeleteBytes(body, "prompt_cache_retention")
	body, _ = sjson.DeleteBytes(body, "safety_identifier")
	body, _ = sjson.DeleteBytes(body, "stream_options")
	body, _ = sjson.SetBytes(body, "stream", false)
	body = normalizeCodexInstructions(body)

	enc, err := tokenizerForCodexModel(baseModel)
	if err != nil {
		return cliproxyexecutor.Response{}, fmt.Errorf("tocodex executor: tokenizer init failed: %w", err)
	}
	count, err := countCodexInputTokens(enc, body)
	if err != nil {
		return cliproxyexecutor.Response{}, fmt.Errorf("tocodex executor: token counting failed: %w", err)
	}
	usageJSON := fmt.Sprintf(`{"response":{"usage":{"input_tokens":%d,"output_tokens":0,"total_tokens":%d}}}`, count, count)
	return cliproxyexecutor.Response{
		Payload: sdktranslator.TranslateTokenCount(ctx, to, from, count, []byte(usageJSON)),
	}, nil
}

func (e *ToCodexExecutor) Refresh(ctx context.Context, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, error) {
	_ = ctx
	return auth, nil
}

func (e *ToCodexExecutor) executeResponses(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, resolved toCodexResolvedConfig) (resp cliproxyexecutor.Response, err error) {
	baseModel := thinking.ParseSuffix(req.Model).ModelName
	reporter := helps.NewUsageReporter(ctx, e.Identifier(), baseModel, auth)
	defer reporter.TrackFailure(ctx, &err)

	from := opts.SourceFormat
	to := sdktranslator.FormatCodex
	originalPayloadSource := req.Payload
	if len(opts.OriginalRequest) > 0 {
		originalPayloadSource = opts.OriginalRequest
	}
	originalPayload := originalPayloadSource
	originalTranslated := sdktranslator.TranslateRequest(from, to, baseModel, originalPayload, false)
	body := sdktranslator.TranslateRequest(from, to, baseModel, req.Payload, false)

	body, err = thinking.ApplyThinking(body, req.Model, from.String(), to.String(), e.Identifier())
	if err != nil {
		return resp, err
	}

	requestedModel := helps.PayloadRequestedModel(opts, req.Model)
	body = helps.ApplyPayloadConfigWithRoot(e.cfg, baseModel, to.String(), "", body, originalTranslated, requestedModel)
	body, _ = sjson.SetBytes(body, "model", baseModel)
	body, _ = sjson.SetBytes(body, "stream", true)
	body, _ = sjson.DeleteBytes(body, "previous_response_id")
	body, _ = sjson.DeleteBytes(body, "prompt_cache_retention")
	body, _ = sjson.DeleteBytes(body, "safety_identifier")
	body, _ = sjson.DeleteBytes(body, "stream_options")
	body = normalizeCodexInstructions(body)

	url := resolveToCodexRequestURL(resolved.BaseURL, resolved.ResponsesPath, toCodexDefaultResponsesPath)
	httpReq, err := e.cacheHelper(ctx, from, url, req, body)
	if err != nil {
		return resp, err
	}
	if err := applyToCodexHeaders(httpReq, auth, resolved, body, true); err != nil {
		return resp, err
	}

	recordToCodexRequest(ctx, e.cfg, http.MethodPost, url, httpReq.Header.Clone(), body, e.Identifier(), auth)
	httpResp, err := helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0).Do(httpReq)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		return resp, err
	}
	helps.RecordAPIResponseMetadata(ctx, e.cfg, httpResp.StatusCode, httpResp.Header.Clone())
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		decodedBody, decErr := decodeResponseBody(httpResp.Body, httpResp.Header.Get("Content-Encoding"))
		if decErr != nil {
			helps.RecordAPIResponseError(ctx, e.cfg, decErr)
			return resp, decErr
		}
		defer closeExecutorBody("tocodex executor", decodedBody)
		b, _ := io.ReadAll(decodedBody)
		helps.AppendAPIResponseChunk(ctx, e.cfg, b)
		helps.LogWithRequestID(ctx).Debugf("request error, error status: %d, error message: %s", httpResp.StatusCode, helps.SummarizeErrorBody(httpResp.Header.Get("Content-Type"), b))
		err = newCodexStatusErr(httpResp.StatusCode, b)
		return resp, err
	}

	decodedBody, decErr := decodeResponseBody(httpResp.Body, httpResp.Header.Get("Content-Encoding"))
	if decErr != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, decErr)
		return resp, decErr
	}
	defer closeExecutorBody("tocodex executor", decodedBody)
	data, err := io.ReadAll(decodedBody)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		return resp, err
	}
	helps.AppendAPIResponseChunk(ctx, e.cfg, data)

	lines := bytes.Split(data, []byte("\n"))
	outputItemsByIndex := make(map[int64][]byte)
	var outputItemsFallback [][]byte
	for _, line := range lines {
		if !bytes.HasPrefix(line, dataTag) {
			continue
		}
		eventData := bytes.TrimSpace(line[5:])
		eventType := gjson.GetBytes(eventData, "type").String()
		if eventType == "response.output_item.done" {
			collectCodexOutputItemDone(eventData, outputItemsByIndex, &outputItemsFallback)
			continue
		}
		if eventType != "response.completed" {
			continue
		}
		if detail, ok := helps.ParseCodexUsage(eventData); ok {
			reporter.Publish(ctx, detail)
		}
		completedData := patchCodexCompletedOutput(eventData, outputItemsByIndex, outputItemsFallback)
		var param any
		out := sdktranslator.TranslateNonStream(ctx, to, from, req.Model, originalPayload, body, completedData, &param)
		return cliproxyexecutor.Response{Payload: out, Headers: httpResp.Header.Clone()}, nil
	}
	err = statusErr{code: 408, msg: "stream error: stream disconnected before completion: stream closed before response.completed"}
	return resp, err
}

func (e *ToCodexExecutor) executeResponsesCompact(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, resolved toCodexResolvedConfig) (resp cliproxyexecutor.Response, err error) {
	baseModel := thinking.ParseSuffix(req.Model).ModelName
	reporter := helps.NewUsageReporter(ctx, e.Identifier(), baseModel, auth)
	defer reporter.TrackFailure(ctx, &err)

	from := opts.SourceFormat
	to := sdktranslator.FormatOpenAIResponse
	originalPayloadSource := req.Payload
	if len(opts.OriginalRequest) > 0 {
		originalPayloadSource = opts.OriginalRequest
	}
	originalPayload := originalPayloadSource
	originalTranslated := sdktranslator.TranslateRequest(from, to, baseModel, originalPayload, false)
	body := sdktranslator.TranslateRequest(from, to, baseModel, req.Payload, false)

	body, err = thinking.ApplyThinking(body, req.Model, from.String(), to.String(), e.Identifier())
	if err != nil {
		return resp, err
	}

	requestedModel := helps.PayloadRequestedModel(opts, req.Model)
	body = helps.ApplyPayloadConfigWithRoot(e.cfg, baseModel, to.String(), "", body, originalTranslated, requestedModel)
	body, _ = sjson.SetBytes(body, "model", baseModel)
	body, _ = sjson.DeleteBytes(body, "stream")
	body = normalizeCodexInstructions(body)

	url := resolveToCodexRequestURL(resolved.BaseURL, resolved.ResponsesCompactPath, toCodexDefaultResponsesCompactPath)
	httpReq, err := e.cacheHelper(ctx, from, url, req, body)
	if err != nil {
		return resp, err
	}
	if err := applyToCodexHeaders(httpReq, auth, resolved, body, false); err != nil {
		return resp, err
	}

	recordToCodexRequest(ctx, e.cfg, http.MethodPost, url, httpReq.Header.Clone(), body, e.Identifier(), auth)
	httpResp, err := helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0).Do(httpReq)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		return resp, err
	}
	helps.RecordAPIResponseMetadata(ctx, e.cfg, httpResp.StatusCode, httpResp.Header.Clone())
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		decodedBody, decErr := decodeResponseBody(httpResp.Body, httpResp.Header.Get("Content-Encoding"))
		if decErr != nil {
			helps.RecordAPIResponseError(ctx, e.cfg, decErr)
			return resp, decErr
		}
		defer closeExecutorBody("tocodex executor", decodedBody)
		b, _ := io.ReadAll(decodedBody)
		helps.AppendAPIResponseChunk(ctx, e.cfg, b)
		helps.LogWithRequestID(ctx).Debugf("request error, error status: %d, error message: %s", httpResp.StatusCode, helps.SummarizeErrorBody(httpResp.Header.Get("Content-Type"), b))
		err = newCodexStatusErr(httpResp.StatusCode, b)
		return resp, err
	}

	decodedBody, decErr := decodeResponseBody(httpResp.Body, httpResp.Header.Get("Content-Encoding"))
	if decErr != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, decErr)
		return resp, decErr
	}
	defer closeExecutorBody("tocodex executor", decodedBody)
	data, err := io.ReadAll(decodedBody)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		return resp, err
	}
	helps.AppendAPIResponseChunk(ctx, e.cfg, data)
	reporter.Publish(ctx, helps.ParseOpenAIUsage(data))
	reporter.EnsurePublished(ctx)
	var param any
	out := sdktranslator.TranslateNonStream(ctx, to, from, req.Model, originalPayload, body, data, &param)
	return cliproxyexecutor.Response{Payload: out, Headers: httpResp.Header.Clone()}, nil
}

func (e *ToCodexExecutor) executeResponsesStream(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, resolved toCodexResolvedConfig) (_ *cliproxyexecutor.StreamResult, err error) {
	baseModel := thinking.ParseSuffix(req.Model).ModelName
	reporter := helps.NewUsageReporter(ctx, e.Identifier(), baseModel, auth)
	defer reporter.TrackFailure(ctx, &err)

	from := opts.SourceFormat
	to := sdktranslator.FormatCodex
	originalPayloadSource := req.Payload
	if len(opts.OriginalRequest) > 0 {
		originalPayloadSource = opts.OriginalRequest
	}
	originalPayload := originalPayloadSource
	originalTranslated := sdktranslator.TranslateRequest(from, to, baseModel, originalPayload, true)
	body := sdktranslator.TranslateRequest(from, to, baseModel, req.Payload, true)

	body, err = thinking.ApplyThinking(body, req.Model, from.String(), to.String(), e.Identifier())
	if err != nil {
		return nil, err
	}

	requestedModel := helps.PayloadRequestedModel(opts, req.Model)
	body = helps.ApplyPayloadConfigWithRoot(e.cfg, baseModel, to.String(), "", body, originalTranslated, requestedModel)
	body, _ = sjson.DeleteBytes(body, "previous_response_id")
	body, _ = sjson.DeleteBytes(body, "prompt_cache_retention")
	body, _ = sjson.DeleteBytes(body, "safety_identifier")
	body, _ = sjson.DeleteBytes(body, "stream_options")
	body, _ = sjson.SetBytes(body, "model", baseModel)
	body = normalizeCodexInstructions(body)

	url := resolveToCodexRequestURL(resolved.BaseURL, resolved.ResponsesPath, toCodexDefaultResponsesPath)
	httpReq, err := e.cacheHelper(ctx, from, url, req, body)
	if err != nil {
		return nil, err
	}
	if err := applyToCodexHeaders(httpReq, auth, resolved, body, true); err != nil {
		return nil, err
	}

	recordToCodexRequest(ctx, e.cfg, http.MethodPost, url, httpReq.Header.Clone(), body, e.Identifier(), auth)
	httpResp, err := helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0).Do(httpReq)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		return nil, err
	}
	helps.RecordAPIResponseMetadata(ctx, e.cfg, httpResp.StatusCode, httpResp.Header.Clone())
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		decodedBody, decErr := decodeResponseBody(httpResp.Body, httpResp.Header.Get("Content-Encoding"))
		if decErr != nil {
			helps.RecordAPIResponseError(ctx, e.cfg, decErr)
			return nil, decErr
		}
		data, readErr := io.ReadAll(decodedBody)
		closeExecutorBody("tocodex executor", decodedBody)
		if readErr != nil {
			helps.RecordAPIResponseError(ctx, e.cfg, readErr)
			return nil, readErr
		}
		helps.AppendAPIResponseChunk(ctx, e.cfg, data)
		helps.LogWithRequestID(ctx).Debugf("request error, error status: %d, error message: %s", httpResp.StatusCode, helps.SummarizeErrorBody(httpResp.Header.Get("Content-Type"), data))
		err = newCodexStatusErr(httpResp.StatusCode, data)
		return nil, err
	}
	decodedBody, decErr := decodeResponseBody(httpResp.Body, httpResp.Header.Get("Content-Encoding"))
	if decErr != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, decErr)
		return nil, decErr
	}

	out := make(chan cliproxyexecutor.StreamChunk)
	go func() {
		defer close(out)
		defer closeExecutorBody("tocodex executor", decodedBody)
		scanner := bufio.NewScanner(decodedBody)
		scanner.Buffer(nil, 52_428_800)
		var param any
		outputItemsByIndex := make(map[int64][]byte)
		var outputItemsFallback [][]byte
		for scanner.Scan() {
			line := scanner.Bytes()
			helps.AppendAPIResponseChunk(ctx, e.cfg, line)
			translatedLine := bytes.Clone(line)

			if bytes.HasPrefix(line, dataTag) {
				data := bytes.TrimSpace(line[5:])
				switch gjson.GetBytes(data, "type").String() {
				case "response.output_item.done":
					collectCodexOutputItemDone(data, outputItemsByIndex, &outputItemsFallback)
				case "response.completed":
					if detail, ok := helps.ParseCodexUsage(data); ok {
						reporter.Publish(ctx, detail)
					}
					data = patchCodexCompletedOutput(data, outputItemsByIndex, outputItemsFallback)
					translatedLine = append([]byte("data: "), data...)
				}
			}

			chunks := sdktranslator.TranslateStream(ctx, to, from, req.Model, originalPayload, body, translatedLine, &param)
			for i := range chunks {
				out <- cliproxyexecutor.StreamChunk{Payload: chunks[i]}
			}
		}
		if errScan := scanner.Err(); errScan != nil {
			helps.RecordAPIResponseError(ctx, e.cfg, errScan)
			reporter.PublishFailure(ctx)
			out <- cliproxyexecutor.StreamChunk{Err: errScan}
		}
	}()
	return &cliproxyexecutor.StreamResult{Headers: httpResp.Header.Clone(), Chunks: out}, nil
}

func (e *ToCodexExecutor) executeChat(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, resolved toCodexResolvedConfig) (resp cliproxyexecutor.Response, err error) {
	baseModel := thinking.ParseSuffix(req.Model).ModelName
	reporter := helps.NewUsageReporter(ctx, e.Identifier(), baseModel, auth)
	defer reporter.TrackFailure(ctx, &err)

	from := opts.SourceFormat
	to := sdktranslator.FormatOpenAI
	originalPayloadSource := req.Payload
	if len(opts.OriginalRequest) > 0 {
		originalPayloadSource = opts.OriginalRequest
	}
	originalPayload := originalPayloadSource
	originalTranslated := sdktranslator.TranslateRequest(from, to, baseModel, originalPayload, opts.Stream)
	translated := sdktranslator.TranslateRequest(from, to, baseModel, req.Payload, opts.Stream)
	requestedModel := helps.PayloadRequestedModel(opts, req.Model)
	translated = helps.ApplyPayloadConfigWithRoot(e.cfg, baseModel, to.String(), "", translated, originalTranslated, requestedModel)
	translated, err = thinking.ApplyThinking(translated, req.Model, from.String(), to.String(), e.Identifier())
	if err != nil {
		return resp, err
	}

	url := resolveToCodexRequestURL(resolved.BaseURL, resolved.ChatPath, toCodexDefaultChatPath)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(translated))
	if err != nil {
		return resp, err
	}
	if err := applyToCodexHeaders(httpReq, auth, resolved, translated, false); err != nil {
		return resp, err
	}

	recordToCodexRequest(ctx, e.cfg, http.MethodPost, url, httpReq.Header.Clone(), translated, e.Identifier(), auth)
	httpResp, err := helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0).Do(httpReq)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		return resp, err
	}
	helps.RecordAPIResponseMetadata(ctx, e.cfg, httpResp.StatusCode, httpResp.Header.Clone())
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		decodedBody, decErr := decodeResponseBody(httpResp.Body, httpResp.Header.Get("Content-Encoding"))
		if decErr != nil {
			helps.RecordAPIResponseError(ctx, e.cfg, decErr)
			return resp, decErr
		}
		defer closeExecutorBody("tocodex executor", decodedBody)
		b, _ := io.ReadAll(decodedBody)
		helps.AppendAPIResponseChunk(ctx, e.cfg, b)
		helps.LogWithRequestID(ctx).Debugf("request error, error status: %d, error message: %s", httpResp.StatusCode, helps.SummarizeErrorBody(httpResp.Header.Get("Content-Type"), b))
		err = newCodexStatusErr(httpResp.StatusCode, b)
		return resp, err
	}

	decodedBody, decErr := decodeResponseBody(httpResp.Body, httpResp.Header.Get("Content-Encoding"))
	if decErr != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, decErr)
		return resp, decErr
	}
	defer closeExecutorBody("tocodex executor", decodedBody)
	body, err := io.ReadAll(decodedBody)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		return resp, err
	}
	helps.AppendAPIResponseChunk(ctx, e.cfg, body)
	reporter.Publish(ctx, helps.ParseOpenAIUsage(body))
	reporter.EnsurePublished(ctx)
	var param any
	out := sdktranslator.TranslateNonStream(ctx, to, from, req.Model, originalPayload, translated, body, &param)
	return cliproxyexecutor.Response{Payload: out, Headers: httpResp.Header.Clone()}, nil
}

func (e *ToCodexExecutor) executeChatStream(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, resolved toCodexResolvedConfig) (_ *cliproxyexecutor.StreamResult, err error) {
	baseModel := thinking.ParseSuffix(req.Model).ModelName
	reporter := helps.NewUsageReporter(ctx, e.Identifier(), baseModel, auth)
	defer reporter.TrackFailure(ctx, &err)

	from := opts.SourceFormat
	to := sdktranslator.FormatOpenAI
	originalPayloadSource := req.Payload
	if len(opts.OriginalRequest) > 0 {
		originalPayloadSource = opts.OriginalRequest
	}
	originalPayload := originalPayloadSource
	originalTranslated := sdktranslator.TranslateRequest(from, to, baseModel, originalPayload, true)
	translated := sdktranslator.TranslateRequest(from, to, baseModel, req.Payload, true)
	requestedModel := helps.PayloadRequestedModel(opts, req.Model)
	translated = helps.ApplyPayloadConfigWithRoot(e.cfg, baseModel, to.String(), "", translated, originalTranslated, requestedModel)
	translated, err = thinking.ApplyThinking(translated, req.Model, from.String(), to.String(), e.Identifier())
	if err != nil {
		return nil, err
	}
	translated, _ = sjson.SetBytes(translated, "stream_options.include_usage", true)

	url := resolveToCodexRequestURL(resolved.BaseURL, resolved.ChatPath, toCodexDefaultChatPath)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(translated))
	if err != nil {
		return nil, err
	}
	if err := applyToCodexHeaders(httpReq, auth, resolved, translated, true); err != nil {
		return nil, err
	}
	httpReq.Header.Set("Cache-Control", "no-cache")

	recordToCodexRequest(ctx, e.cfg, http.MethodPost, url, httpReq.Header.Clone(), translated, e.Identifier(), auth)
	httpResp, err := helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0).Do(httpReq)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		return nil, err
	}
	helps.RecordAPIResponseMetadata(ctx, e.cfg, httpResp.StatusCode, httpResp.Header.Clone())
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		decodedBody, decErr := decodeResponseBody(httpResp.Body, httpResp.Header.Get("Content-Encoding"))
		if decErr != nil {
			helps.RecordAPIResponseError(ctx, e.cfg, decErr)
			return nil, decErr
		}
		b, _ := io.ReadAll(decodedBody)
		helps.AppendAPIResponseChunk(ctx, e.cfg, b)
		helps.LogWithRequestID(ctx).Debugf("request error, error status: %d, error message: %s", httpResp.StatusCode, helps.SummarizeErrorBody(httpResp.Header.Get("Content-Type"), b))
		closeExecutorBody("tocodex executor", decodedBody)
		err = newCodexStatusErr(httpResp.StatusCode, b)
		return nil, err
	}
	decodedBody, decErr := decodeResponseBody(httpResp.Body, httpResp.Header.Get("Content-Encoding"))
	if decErr != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, decErr)
		return nil, decErr
	}

	out := make(chan cliproxyexecutor.StreamChunk)
	go func() {
		defer close(out)
		defer closeExecutorBody("tocodex executor", decodedBody)
		scanner := bufio.NewScanner(decodedBody)
		scanner.Buffer(nil, 52_428_800)
		var param any
		sawDone := false
		for scanner.Scan() {
			line := bytes.Clone(scanner.Bytes())
			helps.AppendAPIResponseChunk(ctx, e.cfg, line)
			if bytes.Equal(bytes.TrimSpace(line), []byte("data: [DONE]")) || bytes.Equal(bytes.TrimSpace(line), []byte("[DONE]")) {
				sawDone = true
			}
			chunks := sdktranslator.TranslateStream(ctx, to, from, req.Model, originalPayload, translated, line, &param)
			for i := range chunks {
				out <- cliproxyexecutor.StreamChunk{Payload: chunks[i]}
			}
		}
		if errScan := scanner.Err(); errScan != nil {
			helps.RecordAPIResponseError(ctx, e.cfg, errScan)
			reporter.PublishFailure(ctx)
			out <- cliproxyexecutor.StreamChunk{Err: errScan}
			return
		}
		if !sawDone {
			chunks := sdktranslator.TranslateStream(ctx, to, from, req.Model, originalPayload, translated, []byte("data: [DONE]"), &param)
			for i := range chunks {
				out <- cliproxyexecutor.StreamChunk{Payload: chunks[i]}
			}
		}
		reporter.EnsurePublished(ctx)
	}()
	return &cliproxyexecutor.StreamResult{Headers: httpResp.Header.Clone(), Chunks: out}, nil
}

func (e *ToCodexExecutor) resolveRequestConfig(auth *cliproxyauth.Auth) (tocodexResolvedConfig, error) {
	resolved := toCodexResolvedConfig{
		RequestMode:          "responses",
		ChatPath:             toCodexDefaultChatPath,
		ResponsesPath:        toCodexDefaultResponsesPath,
		ResponsesCompactPath: toCodexDefaultResponsesCompactPath,
	}
	if auth == nil {
		return resolved, statusErr{code: http.StatusUnauthorized, msg: "missing ToCodex auth"}
	}
	if auth.Attributes != nil {
		resolved.APIKey = strings.TrimSpace(auth.Attributes["api_key"])
		resolved.BaseURL = strings.TrimSpace(auth.Attributes["base_url"])
	}
	attrSecretHash := ""
	if auth.Attributes != nil {
		attrSecretHash = strings.TrimSpace(auth.Attributes["hmac_secret_hash"])
	}
	if e == nil || e.cfg == nil {
		return validateToCodexResolvedConfig(resolved)
	}
	for i := range e.cfg.ToCodexKey {
		entry := &e.cfg.ToCodexKey[i]
		cfgBase := strings.TrimSpace(entry.BaseURL)
		if resolved.BaseURL != "" && cfgBase != "" && !strings.EqualFold(cfgBase, resolved.BaseURL) {
			continue
		}
		for _, keyEntry := range entry.EffectiveAPIKeyEntries() {
			if !strings.EqualFold(strings.TrimSpace(keyEntry.APIKey), resolved.APIKey) {
				continue
			}
			if attrSecretHash != "" && util.SHA256Hex(keyEntry.HMACSecret) != attrSecretHash {
				continue
			}
			resolved.HMACSecret = strings.TrimSpace(keyEntry.HMACSecret)
			if resolved.BaseURL == "" {
				resolved.BaseURL = cfgBase
			}
			resolved.RequestMode = normalizeToCodexExecutionMode(entry.RequestMode)
			resolved.ChatPath = config.NormalizeRequestPathOrURL(entry.ChatPath, toCodexDefaultChatPath)
			resolved.ResponsesPath = config.NormalizeRequestPathOrURL(entry.ResponsesPath, toCodexDefaultResponsesPath)
			resolved.ResponsesCompactPath = config.NormalizeRequestPathOrURL(entry.ResponsesCompactPath, toCodexDefaultResponsesCompactPath)
			return validateToCodexResolvedConfig(resolved)
		}
	}
	return validateToCodexResolvedConfig(resolved)
}

func validateToCodexResolvedConfig(resolved toCodexResolvedConfig) (tocodexResolvedConfig, error) {
	resolved.RequestMode = normalizeToCodexExecutionMode(resolved.RequestMode)
	resolved.ChatPath = config.NormalizeRequestPathOrURL(resolved.ChatPath, toCodexDefaultChatPath)
	resolved.ResponsesPath = config.NormalizeRequestPathOrURL(resolved.ResponsesPath, toCodexDefaultResponsesPath)
	resolved.ResponsesCompactPath = config.NormalizeRequestPathOrURL(resolved.ResponsesCompactPath, toCodexDefaultResponsesCompactPath)
	if resolved.BaseURL == "" {
		return resolved, statusErr{code: http.StatusUnauthorized, msg: "missing ToCodex baseURL"}
	}
	if resolved.APIKey == "" {
		return resolved, statusErr{code: http.StatusUnauthorized, msg: "missing ToCodex api_key"}
	}
	if resolved.HMACSecret == "" {
		return resolved, statusErr{code: http.StatusUnauthorized, msg: "missing ToCodex hmac_secret"}
	}
	return resolved, nil
}

func normalizeToCodexExecutionMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "chat":
		return "chat"
	default:
		return "responses"
	}
}

func resolveToCodexRequestURL(baseURL, pathOrURL, fallback string) string {
	normalized := config.NormalizeRequestPathOrURL(pathOrURL, fallback)
	if normalized == "" {
		return ""
	}
	if strings.Contains(normalized, "://") {
		return normalized
	}
	return strings.TrimSuffix(strings.TrimSpace(baseURL), "/") + normalized
}

func applyToCodexHeaders(r *http.Request, auth *cliproxyauth.Auth, resolved toCodexResolvedConfig, rawBody []byte, stream bool) error {
	if r == nil {
		return nil
	}
	var attrs map[string]string
	if auth != nil {
		attrs = auth.Attributes
	}
	util.ApplyCustomHeadersFromAttrs(r, attrs)

	r.Header.Set("Content-Type", "application/json")
	if stream {
		r.Header.Set("Accept", "text/event-stream")
	} else {
		r.Header.Set("Accept", "application/json")
	}
	r.Header.Set("Accept-Encoding", "br, gzip, deflate")
	r.Header.Set("Accept-Language", "*")
	r.Header.Set("Authorization", "Bearer "+resolved.APIKey)
	r.Header.Set("Connection", "keep-alive")
	r.Header.Set("HTTP-Referer", toCodexFixedReferer)
	r.Header.Set("Sec-Fetch-Mode", "cors")
	r.Header.Set("User-Agent", toCodexFixedUserAgent)
	r.Header.Set("X-Title", toCodexFixedTitle)

	if r.URL != nil && strings.TrimSpace(r.URL.Host) != "" {
		r.Host = r.URL.Host
		r.Header.Set("Host", r.URL.Host)
	}

	contentLength := int64(-1)
	if rawBody != nil {
		contentLength = int64(len(rawBody))
	}
	if contentLength < 0 && r.ContentLength >= 0 {
		contentLength = r.ContentLength
	}
	if contentLength >= 0 {
		r.ContentLength = contentLength
		r.Header.Set("Content-Length", fmt.Sprintf("%d", contentLength))
	}

	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	nonce := strings.TrimSpace(r.Header.Get("X-ToCodex-Nonce"))
	if nonce == "" {
		nonce = uuid.NewString()
	}
	signature := buildToCodexSignature(timestamp, nonce, r.Method, tocodexSignaturePath(r.URL), resolved.HMACSecret)
	r.Header.Set("X-ToCodex-Timestamp", timestamp)
	r.Header.Set("X-ToCodex-Nonce", nonce)
	r.Header.Set("X-ToCodex-Sig", signature)
	return nil
}

func buildToCodexSignature(timestamp, nonce, method, path, secret string) string {
	raw := fmt.Sprintf("%s:%s:%s:%s", strings.TrimSpace(timestamp), strings.TrimSpace(nonce), strings.ToUpper(strings.TrimSpace(method)), strings.TrimSpace(path))
	sum := hmac.New(sha256.New, []byte(strings.TrimSpace(secret)))
	sum.Write([]byte(raw))
	return hex.EncodeToString(sum.Sum(nil))
}

func tocodexSignaturePath(target *url.URL) string {
	if target == nil {
		return "/"
	}
	path := target.EscapedPath()
	if strings.TrimSpace(path) == "" {
		path = "/"
	}
	if strings.TrimSpace(target.RawQuery) != "" {
		path += "?" + target.RawQuery
	}
	return path
}

func recordToCodexRequest(ctx context.Context, cfg *config.Config, method, url string, headers http.Header, body []byte, provider string, auth *cliproxyauth.Auth) {
	var authID, authLabel, authType, authValue string
	if auth != nil {
		authID = auth.ID
		authLabel = auth.Label
		authType, authValue = auth.AccountInfo()
	}
	helps.RecordAPIRequest(ctx, cfg, helps.UpstreamRequestLog{
		URL:       url,
		Method:    method,
		Headers:   headers,
		Body:      body,
		Provider:  provider,
		AuthID:    authID,
		AuthLabel: authLabel,
		AuthType:  authType,
		AuthValue: authValue,
	})
}

func closeExecutorBody(prefix string, body io.Closer) {
	if body == nil {
		return
	}
	if err := body.Close(); err != nil {
		log.Errorf("%s: close response body error: %v", prefix, err)
	}
}
