package management

import (
	"fmt"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/util"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/watcher/synthesizer"
)

type geminiKeyWithAuthIndex struct {
	config.GeminiKey
	AuthIndex string `json:"auth-index,omitempty"`
}

type claudeKeyWithAuthIndex struct {
	config.ClaudeKey
	AuthIndex string `json:"auth-index,omitempty"`
}

type codexAPIKeyEntryWithAuthIndex struct {
	config.CodexAPIKeyEntry
	AuthIndex string `json:"auth-index,omitempty"`
}

type codexKeyWithAuthIndex struct {
	APIKey         string                          `json:"api-key"`
	APIKeyEntries  []codexAPIKeyEntryWithAuthIndex `json:"api-key-entries,omitempty"`
	Priority       int                             `json:"priority,omitempty"`
	Prefix         string                          `json:"prefix,omitempty"`
	BaseURL        string                          `json:"base-url"`
	Websockets     bool                            `json:"websockets,omitempty"`
	ProxyURL       string                          `json:"proxy-url"`
	Models         []config.CodexModel             `json:"models"`
	Headers        map[string]string               `json:"headers,omitempty"`
	ExcludedModels []string                        `json:"excluded-models,omitempty"`
	AuthIndex      string                          `json:"auth-index,omitempty"`
}

type tocodexAPIKeyEntryWithAuthIndex struct {
	config.ToCodexAPIKeyEntry
	AuthIndex string `json:"auth-index,omitempty"`
}

type tocodexKeyWithAuthIndex struct {
	APIKey               string                            `json:"api-key"`
	HMACSecret           string                            `json:"hmac-secret,omitempty"`
	APIKeyEntries        []tocodexAPIKeyEntryWithAuthIndex `json:"api-key-entries,omitempty"`
	Priority             int                               `json:"priority,omitempty"`
	Prefix               string                            `json:"prefix,omitempty"`
	BaseURL              string                            `json:"base-url"`
	ProxyURL             string                            `json:"proxy-url,omitempty"`
	RequestMode          string                            `json:"request-mode,omitempty"`
	ChatPath             string                            `json:"chat-path,omitempty"`
	ResponsesPath        string                            `json:"responses-path,omitempty"`
	ResponsesCompactPath string                            `json:"responses-compact-path,omitempty"`
	ModelsPath           string                            `json:"models-path,omitempty"`
	TestPath             string                            `json:"test-path,omitempty"`
	Models               []config.CodexModel               `json:"models,omitempty"`
	Headers              map[string]string                 `json:"headers,omitempty"`
	ExcludedModels       []string                          `json:"excluded-models,omitempty"`
	AuthIndex            string                            `json:"auth-index,omitempty"`
}

type vertexCompatKeyWithAuthIndex struct {
	config.VertexCompatKey
	AuthIndex string `json:"auth-index,omitempty"`
}

type openAICompatibilityAPIKeyWithAuthIndex struct {
	config.OpenAICompatibilityAPIKey
	AuthIndex string `json:"auth-index,omitempty"`
}

type openAICompatibilityWithAuthIndex struct {
	Name          string                                   `json:"name"`
	Priority      int                                      `json:"priority,omitempty"`
	Prefix        string                                   `json:"prefix,omitempty"`
	BaseURL       string                                   `json:"base-url"`
	APIKeyEntries []openAICompatibilityAPIKeyWithAuthIndex `json:"api-key-entries,omitempty"`
	Models        []config.OpenAICompatibilityModel        `json:"models,omitempty"`
	Headers       map[string]string                        `json:"headers,omitempty"`
	AuthIndex     string                                   `json:"auth-index,omitempty"`
}

func (h *Handler) liveAuthIndexByID() map[string]string {
	out := map[string]string{}
	if h == nil {
		return out
	}
	h.mu.Lock()
	manager := h.authManager
	h.mu.Unlock()
	if manager == nil {
		return out
	}
	// authManager.List() returns clones, so EnsureIndex only affects these copies.
	for _, auth := range manager.List() {
		if auth == nil {
			continue
		}
		id := strings.TrimSpace(auth.ID)
		if id == "" {
			continue
		}
		idx := strings.TrimSpace(auth.Index)
		if idx == "" {
			idx = auth.EnsureIndex()
		}
		if idx == "" {
			continue
		}
		out[id] = idx
	}
	return out
}

func (h *Handler) geminiKeysWithAuthIndex() []geminiKeyWithAuthIndex {
	if h == nil {
		return nil
	}
	liveIndexByID := h.liveAuthIndexByID()

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cfg == nil {
		return nil
	}

	idGen := synthesizer.NewStableIDGenerator()
	out := make([]geminiKeyWithAuthIndex, len(h.cfg.GeminiKey))
	for i := range h.cfg.GeminiKey {
		entry := h.cfg.GeminiKey[i]
		authIndex := ""
		if key := strings.TrimSpace(entry.APIKey); key != "" {
			id, _ := idGen.Next("gemini:apikey", key, entry.BaseURL)
			authIndex = liveIndexByID[id]
		}
		out[i] = geminiKeyWithAuthIndex{
			GeminiKey: entry,
			AuthIndex: authIndex,
		}
	}
	return out
}

func (h *Handler) claudeKeysWithAuthIndex() []claudeKeyWithAuthIndex {
	if h == nil {
		return nil
	}
	liveIndexByID := h.liveAuthIndexByID()

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cfg == nil {
		return nil
	}

	idGen := synthesizer.NewStableIDGenerator()
	out := make([]claudeKeyWithAuthIndex, len(h.cfg.ClaudeKey))
	for i := range h.cfg.ClaudeKey {
		entry := h.cfg.ClaudeKey[i]
		authIndex := ""
		if key := strings.TrimSpace(entry.APIKey); key != "" {
			id, _ := idGen.Next("claude:apikey", key, entry.BaseURL)
			authIndex = liveIndexByID[id]
		}
		out[i] = claudeKeyWithAuthIndex{
			ClaudeKey: entry,
			AuthIndex: authIndex,
		}
	}
	return out
}

func (h *Handler) codexKeysWithAuthIndex() []codexKeyWithAuthIndex {
	if h == nil {
		return nil
	}
	liveIndexByID := h.liveAuthIndexByID()

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cfg == nil {
		return nil
	}

	idGen := synthesizer.NewStableIDGenerator()
	out := make([]codexKeyWithAuthIndex, len(h.cfg.CodexKey))
	for i := range h.cfg.CodexKey {
		entry := h.cfg.CodexKey[i]
		response := codexKeyWithAuthIndex{
			APIKey:         entry.APIKey,
			Priority:       entry.Priority,
			Prefix:         entry.Prefix,
			BaseURL:        entry.BaseURL,
			Websockets:     entry.Websockets,
			ProxyURL:       entry.ProxyURL,
			Models:         entry.Models,
			Headers:        entry.Headers,
			ExcludedModels: entry.ExcludedModels,
		}
		if len(entry.APIKeyEntries) == 0 {
			if key := strings.TrimSpace(entry.APIKey); key != "" {
				id, _ := idGen.Next("codex:apikey", key, entry.BaseURL)
				response.AuthIndex = liveIndexByID[id]
			}
		} else {
			response.APIKey = ""
			response.APIKeyEntries = make([]codexAPIKeyEntryWithAuthIndex, len(entry.APIKeyEntries))
			for j := range entry.APIKeyEntries {
				apiKeyEntry := entry.APIKeyEntries[j]
				proxyURL := strings.TrimSpace(apiKeyEntry.ProxyURL)
				if proxyURL == "" {
					proxyURL = strings.TrimSpace(entry.ProxyURL)
				}
				id, _ := idGen.Next("codex:apikey", apiKeyEntry.APIKey, entry.BaseURL, proxyURL)
				response.APIKeyEntries[j] = codexAPIKeyEntryWithAuthIndex{
					CodexAPIKeyEntry: apiKeyEntry,
					AuthIndex:        liveIndexByID[id],
				}
			}
		}
		out[i] = response
	}
	return out
}

func (h *Handler) tocodexKeysWithAuthIndex() []tocodexKeyWithAuthIndex {
	if h == nil {
		return nil
	}
	liveIndexByID := h.liveAuthIndexByID()

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cfg == nil {
		return nil
	}

	idGen := synthesizer.NewStableIDGenerator()
	out := make([]tocodexKeyWithAuthIndex, len(h.cfg.ToCodexKey))
	for i := range h.cfg.ToCodexKey {
		entry := h.cfg.ToCodexKey[i]
		response := tocodexKeyWithAuthIndex{
			APIKey:               entry.APIKey,
			HMACSecret:           entry.HMACSecret,
			Priority:             entry.Priority,
			Prefix:               entry.Prefix,
			BaseURL:              entry.BaseURL,
			ProxyURL:             entry.ProxyURL,
			RequestMode:          entry.RequestMode,
			ChatPath:             entry.ChatPath,
			ResponsesPath:        entry.ResponsesPath,
			ResponsesCompactPath: entry.ResponsesCompactPath,
			ModelsPath:           entry.ModelsPath,
			TestPath:             entry.TestPath,
			Models:               entry.Models,
			Headers:              entry.Headers,
			ExcludedModels:       entry.ExcludedModels,
		}
		if len(entry.APIKeyEntries) == 0 {
			if key := strings.TrimSpace(entry.APIKey); key != "" && strings.TrimSpace(entry.HMACSecret) != "" {
				id, _ := idGen.Next("tocodex:apikey", key, util.SHA256Hex(entry.HMACSecret), entry.BaseURL, entry.ProxyURL)
				response.AuthIndex = liveIndexByID[id]
			}
		} else {
			response.APIKey = ""
			response.HMACSecret = ""
			response.APIKeyEntries = make([]tocodexAPIKeyEntryWithAuthIndex, len(entry.APIKeyEntries))
			for j := range entry.APIKeyEntries {
				apiKeyEntry := entry.APIKeyEntries[j]
				proxyURL := strings.TrimSpace(apiKeyEntry.ProxyURL)
				if proxyURL == "" {
					proxyURL = strings.TrimSpace(entry.ProxyURL)
				}
				id, _ := idGen.Next("tocodex:apikey", apiKeyEntry.APIKey, util.SHA256Hex(apiKeyEntry.HMACSecret), entry.BaseURL, proxyURL)
				response.APIKeyEntries[j] = tocodexAPIKeyEntryWithAuthIndex{
					ToCodexAPIKeyEntry: apiKeyEntry,
					AuthIndex:          liveIndexByID[id],
				}
			}
		}
		out[i] = response
	}
	return out
}

func (h *Handler) vertexCompatKeysWithAuthIndex() []vertexCompatKeyWithAuthIndex {
	if h == nil {
		return nil
	}
	liveIndexByID := h.liveAuthIndexByID()

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cfg == nil {
		return nil
	}

	idGen := synthesizer.NewStableIDGenerator()
	out := make([]vertexCompatKeyWithAuthIndex, len(h.cfg.VertexCompatAPIKey))
	for i := range h.cfg.VertexCompatAPIKey {
		entry := h.cfg.VertexCompatAPIKey[i]
		id, _ := idGen.Next("vertex:apikey", entry.APIKey, entry.BaseURL, entry.ProxyURL)
		authIndex := liveIndexByID[id]
		out[i] = vertexCompatKeyWithAuthIndex{
			VertexCompatKey: entry,
			AuthIndex:       authIndex,
		}
	}
	return out
}

func (h *Handler) openAICompatibilityWithAuthIndex() []openAICompatibilityWithAuthIndex {
	if h == nil {
		return nil
	}
	liveIndexByID := h.liveAuthIndexByID()

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cfg == nil {
		return nil
	}

	normalized := normalizedOpenAICompatibilityEntries(h.cfg.OpenAICompatibility)
	out := make([]openAICompatibilityWithAuthIndex, len(normalized))
	idGen := synthesizer.NewStableIDGenerator()
	for i := range normalized {
		entry := normalized[i]
		providerName := strings.ToLower(strings.TrimSpace(entry.Name))
		if providerName == "" {
			providerName = "openai-compatibility"
		}
		idKind := fmt.Sprintf("openai-compatibility:%s", providerName)

		response := openAICompatibilityWithAuthIndex{
			Name:      entry.Name,
			Priority:  entry.Priority,
			Prefix:    entry.Prefix,
			BaseURL:   entry.BaseURL,
			Models:    entry.Models,
			Headers:   entry.Headers,
			AuthIndex: "",
		}
		if len(entry.APIKeyEntries) == 0 {
			id, _ := idGen.Next(idKind, entry.BaseURL)
			response.AuthIndex = liveIndexByID[id]
		} else {
			response.APIKeyEntries = make([]openAICompatibilityAPIKeyWithAuthIndex, len(entry.APIKeyEntries))
			for j := range entry.APIKeyEntries {
				apiKeyEntry := entry.APIKeyEntries[j]
				id, _ := idGen.Next(idKind, apiKeyEntry.APIKey, entry.BaseURL, apiKeyEntry.ProxyURL)
				response.APIKeyEntries[j] = openAICompatibilityAPIKeyWithAuthIndex{
					OpenAICompatibilityAPIKey: apiKeyEntry,
					AuthIndex:                 liveIndexByID[id],
				}
			}
		}
		out[i] = response
	}
	return out
}
