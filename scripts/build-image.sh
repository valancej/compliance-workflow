#!/bin/bash

set -Eeuo pipefail
# Convert labels from the compliance manifest into command line args for build

echo "Converting labels from hardening manifest into command line args"
image_labels=$(while IFS= read -r label; do
  echo "--label=$label"
done < "artifacts/image-labels.env")

IFS=$'\n'
# Builds image from Dockerfile

docker build . \
  $image_labels \
  --label="org.opencontainers.image.created=$(date +%Y-%m-%d)" \
  --label="org.opencontainers.image.revision=$GITHUB_SHA" \
  --tag="localbuild/$IMAGE_NAME:latest" \
  --tag="$GHCR/$GITHUB_ACTOR/$IMAGE_NAME:latest" \
  --tag="$GHCR/$GITHUB_ACTOR/$IMAGE_NAME:$GITHUB_SHA"

