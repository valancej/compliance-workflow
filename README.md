# Example build and deploy workflow 

## Build job

1. Scan directory with Grype
2. Build container image
3. Scan built image with Grype
4. Push image to GHCR

## Deploy job

[Deployment repo](https://github.com/valancej/compliance-deployment)
[Reports repo](https://github.com/valancej/compliance-reports)

**Requires build job**

1. Update deployment repo with latest image and other deployment information
2. Argo syncs updated manifests from deployment repo
