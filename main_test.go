package main

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRoleJSON(t *testing.T) {
	for _, tc := range []struct {
		name     string
		data     string
		wantErr  bool
		wantName string
	}{
		{"valid", `{"name":"roles/test","included_permissions":["test.read"]}`, false, "roles/test"},
		{"duplicate names", `{"name":"roles/a","name":"roles/b"}`, true, ""},
		{"invalid UTF-8", "{\"name\":\"\xff\"}", true, ""},
		{"case sensitive", `{"Name":"roles/test"}`, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var role Role
			err := json.Unmarshal([]byte(tc.data), &role)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Unmarshal error = %v, want error %v", err, tc.wantErr)
			}
			if !tc.wantErr && role.Name != tc.wantName {
				t.Fatalf("name = %q, want %q", role.Name, tc.wantName)
			}
		})
	}

	data, err := json.Marshal(Role{Name: "roles/test"}, jsontext.WithIndent("  "))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "\n  \"included_permissions\": []") {
		t.Fatalf("unexpected role JSON: %s", data)
	}
}

func TestGenerateHTMLJSON(t *testing.T) {
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, name := range []string{"assets", "templates"} {
		if err := os.Symlink(filepath.Join(root, name), filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "iam"), 0755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"timestamp.json": `{"last_crawled":"2026-01-01T00:00:00Z"}`,
		"role.json":      `{"name":"roles/test","title":"Test","included_permissions":["test.read"]}`,
		"invalid.json":   `{"name":"roles/bad","name":"roles/duplicate"}`,
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, "iam", name), []byte(data), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(root); err != nil {
			t.Error(err)
		}
	})
	t.Setenv("WEBSITE", "https://example.com")
	if err := generateHTML(); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"roles-list.json":       `["roles/test"]`,
		"permissions-list.json": `["test.read"]`,
		"roles-metadata.json":   `{"roles/test":{"deprecated":false,"title":"Test","type":"Predefined"}}`,
	} {
		got, err := os.ReadFile(filepath.Join("html", name))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Errorf("%s = %s, want %s", name, got, want)
		}
	}
}
