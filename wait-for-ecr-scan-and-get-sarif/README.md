# Wait for ECR Scan and get Sarif GitHub Action

### Easily upload coverage reports to Codecov from GitHub Actions

## Usage

To integrate with your Actions pipeline, specify the name of this repository with a branch or tag number (`main` is recommended) as a `step` within your `workflow.yml` file.

Inside your `.github/workflows/workflow.yml` file:

```yaml
steps:
  - uses: discoveryedu/github-actions-library/wait-for-ecr-scan-and-get-sarif@main
    with:
      repository_name: "docker/repo"
      image_tag: "main"
      aws_region: "us-east-2"
      output_file: "report.sarif"
```

After you run this shared workflow you might want to upload the results to github.
That looks like this:

```yaml
steps:
  - name: Upload SARIF file
    uses: github/codeql-action/upload-sarif@v3
    with:
      sarif_file: report.sarif
      category: security
```

## Arguments

This Action supports inputs from the user. These inputs, along with their descriptions and usage contexts, are listed in the table below:

| Input             | Description                                                                                            |  Required  |
| :---------------- | :----------------------------------------------------------------------------------------------------- | :--------: |
| `repository_name` | ECR repository name                                                                                    | \*Required |
| `image_tag`       | Docker image tag                                                                                       | \*Required |
| `aws_region`      | Region, like us-east-1                                                                                 | \*Required |
| `output_file`     | File location to place the Sarif output file. It is json, but it sometimes uses the `.sarif` extension | \*Required |

### Example full `workflow.yml` using this Action

```yaml
name: "Build container image"
on:
  push:
    branches:
      - main
  workflow_dispatch:
jobs:
  ecr-scan:
    runs-on: ubuntu-latest

    steps:
      # [Probably build and push image to ECR here]

      - name: Run ECR Scan and Get SARIF Report
        uses: sartography/github-actions-library/wait-for-ecr-scan-and-get-sarif@main
        with:
          repository_name: "infr/testcloud2202"
          image_tag: "main"
          aws_region: "us-east-2"
          output_file: "report.sarif"

      - name: Upload SARIF report as artifact
        uses: actions/upload-artifact@v3
        with:
          name: sarif-report
          path: report.sarif

      - name: Upload SARIF file
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: report.sarif
          category: security
```
