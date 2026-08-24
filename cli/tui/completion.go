package tui

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

// CompletionSpec is the command-owned successful completion projection. The
// constructor validates it and takes copies so the session receives one
// immutable value rather than retaining platform or identity state.
type CompletionSpec struct {
	ResolverPath         string
	CAPath               string
	CAFingerprint        string
	PublicVIP            string
	PassthroughVIP       string
	SSOIssuer            string
	AdministratorURL     string
	Username             string
	Password             string
	BrowserGroups        []CompletionGroup
	ProtocolEndpoints    []CompletionEndpoint
	UncategorizedWebApps []CompletionEndpoint
}

type CompletionGroup struct {
	Name      string
	Endpoints []CompletionEndpoint
}

type CompletionEndpoint struct {
	Name string
	URL  string
}

// Completion is valid only when constructed by NewCompletion. Its fields stay
// private so completion data has one validation and copy boundary.
type Completion struct {
	resolverPath         string
	caPath               string
	caFingerprint        string
	publicVIP            string
	passthroughVIP       string
	ssoIssuer            string
	administratorURL     string
	username             string
	password             string
	browserGroups        []CompletionGroup
	protocolEndpoints    []CompletionEndpoint
	uncategorizedWebApps []CompletionEndpoint
	valid                bool
}

func NewCompletion(spec CompletionSpec) (Completion, error) {
	required := [...]struct {
		name  string
		value string
	}{
		{"resolver path", spec.ResolverPath},
		{"CA path", spec.CAPath},
		{"CA fingerprint", spec.CAFingerprint},
		{"public VIP", spec.PublicVIP},
		{"passthrough VIP", spec.PassthroughVIP},
		{"SSO issuer", spec.SSOIssuer},
		{"administrator URL", spec.AdministratorURL},
		{"username", spec.Username},
		{"password", spec.Password},
	}
	for _, field := range required {
		if strings.TrimSpace(field.value) == "" {
			return Completion{}, fmt.Errorf("completion %s is required", field.name)
		}
		if strings.ContainsAny(field.value, "\r\n") {
			return Completion{}, fmt.Errorf("completion %s must be a single line", field.name)
		}
	}
	for _, path := range []string{spec.ResolverPath, spec.CAPath} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return Completion{}, fmt.Errorf("completion path %q must be absolute and clean", path)
		}
	}
	fingerprint, err := hex.DecodeString(spec.CAFingerprint)
	if err != nil || len(fingerprint) != 32 {
		return Completion{}, errors.New("completion CA fingerprint must be SHA-256")
	}
	for _, raw := range []string{spec.PublicVIP, spec.PassthroughVIP} {
		address, err := netip.ParseAddr(raw)
		if err != nil || !address.IsValid() || address.IsUnspecified() ||
			address.IsLoopback() || address.IsMulticast() {
			return Completion{}, fmt.Errorf("completion VIP %q is invalid", raw)
		}
	}
	if err := validateHTTPSURL(spec.SSOIssuer); err != nil {
		return Completion{}, fmt.Errorf("completion SSO issuer: %w", err)
	}
	if err := validateHTTPSURL(spec.AdministratorURL); err != nil {
		return Completion{}, fmt.Errorf("completion administrator URL: %w", err)
	}
	groups, err := copyCompletionGroups(spec.BrowserGroups)
	if err != nil {
		return Completion{}, err
	}
	if len(groups) == 0 {
		return Completion{}, errors.New("completion browser groups are required")
	}
	protocol, err := copyCompletionEndpoints("protocol endpoints", spec.ProtocolEndpoints)
	if err != nil {
		return Completion{}, err
	}
	if len(protocol) == 0 {
		return Completion{}, errors.New("completion protocol endpoints are required")
	}
	applications, err := copyCompletionEndpoints(
		"uncategorized applications", spec.UncategorizedWebApps)
	if err != nil {
		return Completion{}, err
	}
	seenURLs := make(map[string]struct{})
	for _, group := range groups {
		if err := admitCompletionURLs(seenURLs, group.Name, group.Endpoints); err != nil {
			return Completion{}, err
		}
	}
	if err := admitCompletionURLs(seenURLs, "protocol endpoints", protocol); err != nil {
		return Completion{}, err
	}
	if err := admitCompletionURLs(seenURLs, "uncategorized applications", applications); err != nil {
		return Completion{}, err
	}
	return Completion{
		resolverPath: spec.ResolverPath, caPath: spec.CAPath,
		caFingerprint: spec.CAFingerprint, publicVIP: spec.PublicVIP,
		passthroughVIP: spec.PassthroughVIP, ssoIssuer: spec.SSOIssuer,
		administratorURL: spec.AdministratorURL, username: spec.Username,
		password: spec.Password, browserGroups: groups,
		protocolEndpoints: protocol, uncategorizedWebApps: applications,
		valid: true,
	}, nil
}

func admitCompletionURLs(
	seen map[string]struct{},
	label string,
	endpoints []CompletionEndpoint,
) error {
	for _, endpoint := range endpoints {
		if _, duplicate := seen[endpoint.URL]; duplicate {
			return fmt.Errorf("completion URL %q is duplicated across %s", endpoint.URL, label)
		}
		seen[endpoint.URL] = struct{}{}
	}
	return nil
}

func (completion Completion) Valid() bool { return completion.valid }

func (completion Completion) BrowserGroups() []CompletionGroup {
	groups := make([]CompletionGroup, len(completion.browserGroups))
	for index, group := range completion.browserGroups {
		groups[index] = CompletionGroup{
			Name: group.Name, Endpoints: append([]CompletionEndpoint(nil), group.Endpoints...),
		}
	}
	return groups
}

func (completion Completion) ProtocolEndpoints() []CompletionEndpoint {
	return append([]CompletionEndpoint(nil), completion.protocolEndpoints...)
}

func (completion Completion) UncategorizedWebApps() []CompletionEndpoint {
	return append([]CompletionEndpoint(nil), completion.uncategorizedWebApps...)
}

func copyCompletionGroups(groups []CompletionGroup) ([]CompletionGroup, error) {
	result := make([]CompletionGroup, len(groups))
	seen := make(map[string]struct{}, len(groups))
	for index, group := range groups {
		group.Name = strings.TrimSpace(group.Name)
		if group.Name == "" {
			return nil, fmt.Errorf("completion browser group %d has no name", index)
		}
		if _, duplicate := seen[group.Name]; duplicate {
			return nil, fmt.Errorf("completion browser group %q is duplicated", group.Name)
		}
		seen[group.Name] = struct{}{}
		endpoints, err := copyCompletionEndpoints(group.Name, group.Endpoints)
		if err != nil {
			return nil, err
		}
		if len(endpoints) == 0 {
			return nil, fmt.Errorf("completion browser group %q is empty", group.Name)
		}
		result[index] = CompletionGroup{Name: group.Name, Endpoints: endpoints}
	}
	return result, nil
}

func copyCompletionEndpoints(label string, endpoints []CompletionEndpoint) ([]CompletionEndpoint, error) {
	result := make([]CompletionEndpoint, len(endpoints))
	seen := make(map[string]struct{}, len(endpoints))
	for index, endpoint := range endpoints {
		endpoint.Name = strings.TrimSpace(endpoint.Name)
		endpoint.URL = strings.TrimSpace(endpoint.URL)
		if endpoint.Name == "" {
			return nil, fmt.Errorf("completion %s endpoint %d has no name", label, index)
		}
		if err := validateHTTPSURL(endpoint.URL); err != nil {
			return nil, fmt.Errorf("completion %s endpoint %q: %w", label, endpoint.Name, err)
		}
		if _, duplicate := seen[endpoint.URL]; duplicate {
			return nil, fmt.Errorf("completion %s URL %q is duplicated", label, endpoint.URL)
		}
		seen[endpoint.URL] = struct{}{}
		result[index] = endpoint
	}
	return result, nil
}

func validateHTTPSURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" ||
		parsed.User != nil || parsed.Fragment != "" {
		return errors.New("must be an absolute HTTPS URL")
	}
	return nil
}

type completionSection struct {
	name string
	rows []string
}

func (completion Completion) sections() []completionSection {
	sections := make([]completionSection, 0, 4+len(completion.browserGroups))
	sections = append(sections,
		completionSection{name: "Workstation", rows: []string{
			"Resolver  " + completion.resolverPath,
			"CA  " + completion.caPath,
			"CA fingerprint  " + completion.caFingerprint,
			"Public VIP  " + completion.publicVIP,
			"Passthrough VIP  " + completion.passthroughVIP,
		}},
		completionSection{name: "Single sign-on", rows: []string{
			"Issuer  " + completion.ssoIssuer,
			"Administrator  " + completion.administratorURL,
			"Username  " + completion.username,
			"Password  " + completion.password,
		}},
	)
	for _, group := range completion.browserGroups {
		sections = append(sections, endpointSection(group.Name, group.Endpoints))
	}
	if len(completion.uncategorizedWebApps) != 0 {
		sections = append(sections,
			endpointSection("Applications", completion.uncategorizedWebApps))
	}
	if len(completion.protocolEndpoints) != 0 {
		sections = append(sections,
			endpointSection("Token-backed protocol endpoints", completion.protocolEndpoints))
	}
	return sections
}

func endpointSection(name string, endpoints []CompletionEndpoint) completionSection {
	rows := make([]string, len(endpoints))
	for index, endpoint := range endpoints {
		rows[index] = endpoint.Name + "  " + endpoint.URL
	}
	return completionSection{name: name, rows: rows}
}

func renderCompletionText(completion Completion) string {
	if !completion.Valid() {
		return ""
	}
	var builder strings.Builder
	builder.WriteString("Access\n")
	for _, section := range completion.sections() {
		builder.WriteString("\n")
		builder.WriteString(section.name)
		builder.WriteString("\n")
		for _, row := range section.rows {
			builder.WriteString("  ")
			builder.WriteString(row)
			builder.WriteString("\n")
		}
	}
	return strings.TrimSuffix(builder.String(), "\n")
}

func renderCompletion(completion Completion, width int) string {
	if !completion.Valid() {
		return ""
	}
	width = max(width, 40)
	columns := 1
	if width >= 112 {
		columns = 3
	} else if width >= 76 {
		columns = 2
	}
	const gap = 2
	columnWidth := max((width-(columns-1)*gap)/columns, 24)
	buckets := make([][]completionSection, columns)
	heights := make([]int, columns)
	for _, section := range completion.sections() {
		target := 0
		for column := 1; column < columns; column++ {
			if heights[column] < heights[target] {
				target = column
			}
		}
		buckets[target] = append(buckets[target], section)
		heights[target] += len(section.rows) + 2
	}
	rendered := make([]string, 0, columns)
	for column, sections := range buckets {
		if len(sections) == 0 {
			continue
		}
		blocks := make([]string, 0, len(sections))
		for _, section := range sections {
			rows := make([]string, 0, len(section.rows)+1)
			rows = append(rows, headingStyle.Render(ansi.Truncate(section.name, columnWidth, "…")))
			for _, row := range section.rows {
				rows = append(rows, ansi.Truncate(row, columnWidth, "…"))
			}
			blocks = append(blocks, strings.Join(rows, "\n"))
		}
		body := strings.Join(blocks, "\n\n")
		if column < len(buckets)-1 {
			body = lipgloss.NewStyle().Width(columnWidth).PaddingRight(gap).Render(body)
		} else {
			body = lipgloss.NewStyle().Width(columnWidth).Render(body)
		}
		rendered = append(rendered, body)
	}
	body := lipgloss.JoinHorizontal(lipgloss.Top, rendered...)
	return headingStyle.Render("Access") + "\n" + body
}
