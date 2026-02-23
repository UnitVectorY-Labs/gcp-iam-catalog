# Justfile

# Config
port := "8000"
site := "http://localhost:" + port
html_dir := "html"

default: build

# Build
build:
  go build .

# Run tests
test:
  go test ./...

# Site generation
gen:
  WEBSITE="{{site}}" go run . --generate

# Local preview
serve:
  python3 -m http.server {{port}} --directory {{html_dir}}

# Open site in browser
open:
  open "{{site}}"

# Generate and view the site
preview: gen open serve