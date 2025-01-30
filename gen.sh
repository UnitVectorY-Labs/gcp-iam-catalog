#!/bin/bash

rm -rf gcp-iam-catalog
rm -rf html

go build

./gcp-iam-catalog -generate

