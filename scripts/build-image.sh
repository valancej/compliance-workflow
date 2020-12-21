#!/bin/bash

set -Eeuo pipefail

# Create artifacts directory if not exists

mkdir -p artifacts

# Run python script to generate metadata
python scripts/metadata.py

# Convert labels from the compliance manifest into command line args for build
echo "Converting labels from hardening manifest into command line args"
$image_labels=while read label; do
  echo "--label=$label"
done < artifacts/image-labels.env

# Builds image from Dockerfile

docker build . \
  $image_labels \
  --label="org.opencontainers.image.created=$(date +%Y-%m-%d)" \
  --label="org.opencontainers.image.revision=$GITHUB_SHA" \
  --tag="localbuild/$IMAGE_NAME:latest" \
  --tag="$GHCR/$GITHUB_ACTOR/$IMAGE_NAME:latest" \
  --tag="$GHCR/$GITHUB_ACTOR/$IMAGE_NAME:$GITHUB_SHA"

