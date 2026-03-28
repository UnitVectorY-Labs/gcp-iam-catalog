
# Commands for gcp-iam-catalog
default:
  @just --list
# Build gcp-iam-catalog with Go
build:
  go build ./...

# Run tests for gcp-iam-catalog with Go
test:
  go clean -testcache
  go test ./...