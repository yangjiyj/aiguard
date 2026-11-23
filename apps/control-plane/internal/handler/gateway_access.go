package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

type gatewayPublicEndpoint struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// These are display coordinates only. Never resolve or fetch administrator-supplied
// endpoints on the server; connectivity depends on the calling client's network.
func normalizeGatewayPublicURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if len(raw) > 2048 || strings.Contains(raw, "\\") || strings.IndexFunc(raw, unicode.IsControl) >= 0 {
		return "", fmt.Errorf("调用地址格式不正确")
	}
	parsed, err := url.Parse(raw)
	if parsed != nil {
		parsed.Scheme = strings.ToLower(parsed.Scheme)
	}
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || strings.Contains(raw, "#") {
		return "", fmt.Errorf("请输入不含账号密码、查询参数或片段的完整 HTTP 或 HTTPS 地址")
	}
	if parsed.Hostname() == "0.0.0.0" || parsed.Hostname() == "::" {
		return "", fmt.Errorf("请填写客户端可访问的地址，不能使用监听地址")
	}
	if port := parsed.Port(); port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("调用地址端口需在 1 到 65535 之间")
		}
	}
	if strings.HasSuffix(parsed.Host, ":") {
		return "", fmt.Errorf("调用地址端口不正确")
	}
	escaped := strings.ToLower(parsed.EscapedPath())
	if strings.Contains(escaped, "%2f") || strings.Contains(escaped, "%5c") || strings.Contains(escaped, "%25") {
		return "", fmt.Errorf("调用地址路径不正确")
	}
	for _, part := range strings.Split(parsed.Path, "/") {
		if part == "." || part == ".." {
			return "", fmt.Errorf("调用地址路径不能包含相对路径")
		}
	}
	if strings.IndexFunc(parsed.Path, unicode.IsControl) >= 0 {
		return "", fmt.Errorf("调用地址路径不正确")
	}
	return normalizePortalGatewayURL(parsed.String()), nil
}

func parseGatewayPublicEndpoints(raw string) ([]gatewayPublicEndpoint, error) {
	endpoints := []gatewayPublicEndpoint{}
	if strings.TrimSpace(raw) == "" {
		return endpoints, nil
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&endpoints); err != nil || endpoints == nil {
		return nil, fmt.Errorf("调用入口必须为地址列表")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, fmt.Errorf("调用入口格式不正确")
	}
	if len(endpoints) > 20 {
		return nil, fmt.Errorf("最多配置 20 个调用入口")
	}
	urls := map[string]bool{}
	names := map[string]bool{}
	for i := range endpoints {
		ep := &endpoints[i]
		ep.Name = strings.TrimSpace(ep.Name)
		if ep.Name == "" || utf8.RuneCountInString(ep.Name) > 80 || strings.IndexFunc(ep.Name, unicode.IsControl) >= 0 {
			return nil, fmt.Errorf("入口名称需为 1 到 80 个字符")
		}
		value, err := normalizeGatewayPublicURL(ep.URL)
		if err != nil {
			return nil, err
		}
		if value == "" {
			return nil, fmt.Errorf("请填写入口地址")
		}
		ep.URL = value
		if urls[value] || names[ep.Name] {
			return nil, fmt.Errorf("调用入口名称和地址不能重复")
		}
		urls[value] = true
		names[ep.Name] = true
	}
	return endpoints, nil
}

func normalizeGatewayPublicSettings(settings map[string]string) error {
	if raw, ok := settings["gateway_public_base_url"]; ok {
		value, err := normalizeGatewayPublicURL(raw)
		if err != nil {
			return err
		}
		settings["gateway_public_base_url"] = value
	}
	if raw, ok := settings["gateway_public_url_mode"]; ok {
		if raw != "current_origin" && raw != "current_host" && raw != "configured" {
			return fmt.Errorf("调用地址选择方式不正确")
		}
	}
	if raw, ok := settings["gateway_public_endpoints"]; ok {
		endpoints, err := parseGatewayPublicEndpoints(raw)
		if err != nil {
			return err
		}
		encoded, _ := json.Marshal(endpoints)
		settings["gateway_public_endpoints"] = string(encoded)
	}
	return nil
}

func portalGatewayAccessSettings(ctx context.Context, deps *Dependencies, override string) (string, string, []gatewayPublicEndpoint, error) {
	base := ""
	mode := "current_origin"
	endpoints := []gatewayPublicEndpoint{}
	if deps != nil && deps.SystemRepo != nil {
		settings, err := deps.SystemRepo.GetAll(ctx)
		if err != nil {
			return "", "", nil, err
		}
		for _, setting := range settings {
			if setting == nil {
				continue
			}
			switch setting.Key {
			case "gateway_public_base_url":
				base, _ = normalizeGatewayPublicURL(setting.Value)
			case "gateway_public_url_mode":
				if setting.Value == "configured" || setting.Value == "current_host" {
					mode = setting.Value
				}
			case "gateway_public_endpoints":
				if parsed, err := parseGatewayPublicEndpoints(setting.Value); err == nil {
					endpoints = parsed
				}
			}
		}
	}
	if strings.TrimSpace(override) != "" {
		base, _ = normalizeGatewayPublicURL(override)
	}
	return base, mode, endpoints, nil
}
