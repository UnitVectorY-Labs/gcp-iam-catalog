package main

import (
	"bytes"
	"html/template"
	"strings"
	"testing"

	"github.com/dustin/go-humanize"
)

func TestClassifyRoleType(t *testing.T) {
	cases := []struct {
		role string
		want string
	}{
		{"roles/owner", "Basic"},
		{"roles/editor", "Basic"},
		{"roles/viewer", "Basic"},
		{"roles/browser", "Basic"},
		{"roles/aiplatform.serviceAgent", "Service Agent"},
		{"roles/storage.objectAdmin", "Predefined"},
	}

	for _, tc := range cases {
		if got := classifyRoleType(tc.role); got != tc.want {
			t.Errorf("classifyRoleType(%q) = %q, want %q", tc.role, got, tc.want)
		}
	}
}

func TestIsDeprecatedRole(t *testing.T) {
	if !isDeprecatedRole(Role{Stage: "DEPRECATED"}) {
		t.Error("expected DEPRECATED stage role to be deprecated")
	}
	if !isDeprecatedRole(Role{Stage: "GA", Description: "This role is deprecated."}) {
		t.Error("expected role with deprecated description to be deprecated")
	}
	if isDeprecatedRole(Role{Stage: "GA", Description: "Active role"}) {
		t.Error("expected active GA role not to be deprecated")
	}
}

func TestTemplatesRenderWithDesignSystem(t *testing.T) {
	tmpl := template.New("base").Funcs(template.FuncMap{
		"contains": func(s string, substrs ...string) bool {
			sLower := strings.ToLower(s)
			for _, sub := range substrs {
				if strings.Contains(sLower, strings.ToLower(sub)) {
					return true
				}
			}
			return false
		},
		"formatNumber": func(n int) string {
			return humanize.Comma(int64(n))
		},
		"classifyRole": classifyRoleType,
		"displayRoleName": func(roleName string, deprecated bool) string {
			if deprecated {
				return roleName + " (Deprecated)"
			}
			return roleName
		},
	})

	tmpl, err := tmpl.ParseGlob("templates/*.html")
	if err != nil {
		t.Fatalf("failed to parse templates: %v", err)
	}

	pages := []struct {
		name string
		data any
	}{
		{
			name: "index.html",
			data: struct {
				RoleCount       int
				PermissionCount int
				LastCrawled     string
				LastCrawledISO  string
				PathPrefix      string
				ActiveNav       string
			}{
				RoleCount:       2437,
				PermissionCount: 14389,
				LastCrawled:     "November 21, 2026 17:59 UTC",
				LastCrawledISO:  "2026-11-21T17:59:28Z",
				PathPrefix:      "",
				ActiveNav:       "home",
			},
		},
		{
			name: "roles.html",
			data: struct {
				Items          []Role
				LastCrawled    string
				LastCrawledISO string
				PathPrefix     string
				ActiveNav      string
			}{
				Items: []Role{
					{Name: "roles/storage.objectAdmin", Title: "Storage Object Admin", Stage: "GA"},
					{Name: "roles/servicebroker.admin", Title: "Service Broker Admin", Stage: "DEPRECATED", Deprecated: true},
				},
				LastCrawledISO: "2026-11-21T17:59:28Z",
				PathPrefix:     "",
				ActiveNav:      "roles",
			},
		},
		{
			name: "role.html",
			data: Role{
				Name:                "roles/storage.objectAdmin",
				Title:               "Storage Object Admin",
				Description:         "Grants full control over objects.",
				IncludedPermissions: []string{"storage.objects.get", "storage.objects.delete"},
				Stage:               "GA",
				PermissionCount:     2,
				LastCrawledISO:      "2026-11-21T17:59:28Z",
				PathPrefix:          "../",
				ActiveNav:           "roles",
			},
		},
		{
			name: "permissions.html",
			data: struct {
				Items []struct {
					Permission string
				}
				LastCrawled    string
				LastCrawledISO string
				PathPrefix     string
				ActiveNav      string
			}{
				Items: []struct {
					Permission string
				}{
					{Permission: "storage.objects.get"},
				},
				LastCrawledISO: "2026-11-21T17:59:28Z",
				PathPrefix:     "",
				ActiveNav:      "permissions",
			},
		},
		{
			name: "permission.html",
			data: struct {
				RoleCount  int
				Permission string
				Roles      []struct {
					Name       string
					Title      string
					Deprecated bool
				}
				LastCrawled    string
				LastCrawledISO string
				PathPrefix     string
				ActiveNav      string
			}{
				RoleCount:  1,
				Permission: "iam.googleapis.com/roles.get",
				Roles: []struct {
					Name       string
					Title      string
					Deprecated bool
				}{
					{Name: "roles/iam.roleViewer", Title: "Role Viewer"},
				},
				LastCrawledISO: "2026-11-21T17:59:28Z",
				PathPrefix:     "../../",
				ActiveNav:      "permissions",
			},
		},
		{
			name: "search.html",
			data: struct {
				LastCrawled    string
				LastCrawledISO string
				PathPrefix     string
				ActiveNav      string
			}{
				LastCrawledISO: "2026-11-21T17:59:28Z",
				PathPrefix:     "",
				ActiveNav:      "search",
			},
		},
	}

	for _, page := range pages {
		var buf bytes.Buffer
		if err := tmpl.ExecuteTemplate(&buf, page.name, page.data); err != nil {
			t.Fatalf("ExecuteTemplate(%q) failed: %v", page.name, err)
		}
		html := buf.String()
		for _, mustHave := range []string{
			"uvy.css",
			"uvy.js",
			"uvy-standalone-mark-light.svg",
			"uvy-standalone-mark-dark.svg",
			`class="site-header"`,
			`class="uvy-mark"`,
			`id="theme"`,
			`class="site-footer"`,
			"UnitVectorY-Labs",
			"MIT License",
			"<strong>gcp-iam-catalog</strong>",
			`datetime="2026-11-21T17:59:28Z"`,
		} {
			if !strings.Contains(html, mustHave) {
				t.Errorf("%s output missing %q", page.name, mustHave)
			}
		}
	}
}
