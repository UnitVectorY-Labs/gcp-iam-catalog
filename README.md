[![License](https://img.shields.io/badge/license-MIT-blue)](https://opensource.org/licenses/MIT) [![Active](https://img.shields.io/badge/Status-Active-green)](https://guide.unitvectorylabs.com/bestpractices/status/#active)

# gcp-iam-catalog

A comprehensive catalog of GCP IAM roles and permissions, designed to easily identify which roles include a specific permission.

Website: https://gcp-iam-catalog.unitvectorylabs.com/

## Overview

**gcp-iam-catalog** is a website that provides an organized and searchable catalog of GCP IAM roles and their associated permissions. The content is automatically generated by crawling the GCP IAM API, ensuring up-to-date and accurate information.

The rationale around providing this website is that the existing GCP documentation does not provide a simple way to search through the 1,700+ roles that exist in GCP.  Additionally, the 10,000+ permissions in GCP make it challenging to identify which roles grant specific permissions. This site aims to fill that gap.  It is possible that GCP may improve their documentation in the future, making this site obsolete. Until then it aims to provide a useful resource that is kept up to date automatically.

## How It Works

This application is written in Go for both the data collection and site generation processes. The workflow consists of the following steps:

1. **Data Collection:**
    - A GitHub Action [gcp-iam-catalog-crawl.yml](https://github.com/UnitVectorY-Labs/gcp-iam-catalog/blob/main/.github/workflows/gcp-iam-catalog-crawl.yml) runs daily to crawl the GCP IAM API.
    - It fetches all IAM roles and their permissions, saving the data as JSON files in the repository under the [iam](https://github.com/UnitVectorY-Labs/gcp-iam-catalog/tree/main/iam) folder.
2. **Site Generation:**
    - Another GitHub Action [gcp-iam-catalog-generate.yaml](https://github.com/UnitVectorY-Labs/gcp-iam-catalog/blob/main/.github/workflows/gcp-iam-catalog-generate.yaml) triggers upon updates to the `main` branch.
    - It generates static HTML pages from the JSON data using the Go application.
    - Search functionality is implemented using JavaScript client-side.
    - The generated site is automatically deployed to GitHub Pages.
3. **Hosting:**
    - The website is hosted on GitHub Pages.

## Features

- **Role-to-Permission Mapping:** Easily view all permissions associated with each IAM role.
- **Permission-to-Role Mapping:** Identify all roles that grant a specific permission.
- **Automated Updates:** The catalog is updated daily with the latest data from GCP.
- **Search Functionality:** Quickly search for roles or permissions.

## Similar Tools and Resources

The official Google Documetantion for Roles and Permissions:

- [Understanding Roles](https://cloud.google.com/iam/docs/understanding-roles) lists all of the Roles with which permissions they include.  However, wildcards are used which shortens the list but makes it difficult to get an all inclusive list of permissions.
- [Permissions Reference](https://cloud.google.com/iam/docs/permissions-reference) lists all of the permissions and each role that includes that permission.

Other sites that provide a similar functionality include:

- [Permissions Reference for Google Cloud IAM](https://gcp.permissions.cloud/) by [iann0036](https://github.com/iann0036) which is available on GitHub at [iann0036/gcp.permissions.cloud](https://github.com/iann0036/gcp.permissions.cloud) provides a searchable list of permissions and the roles that include them in addition to the APIs associated with each permission.
- [Google Cloud ☁️ Identity and Access Management (IAM)](https://gcloud-iam.nkn-it.de/) by [Cyclenerd](https://github.com/Cyclenerd) which is available on GitHub under [Cyclenerd/google-cloud-iam](https://github.com/Cyclenerd/google-cloud-iam) provides a searchable table of GCP roles and permissions.
