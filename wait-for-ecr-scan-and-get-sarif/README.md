# Wait for ECR Scan and get Sarif GitHub Action

This action is used for integrating AWS ECR Image Scanning with GitHub security.
GitHub security integrates with the Sarif standard, allowing Sarif json files to be uploaded and displayed in the Security tab's code scanning results.
The AWS API's describe-image-scan-findings response is not compatible with the Sarif standard.
This GitHub action waits for AWS image scanning process to complete on a provided tag, takes the AWS API response from describe-image-scan-findings, and converts it to the standard Sarif format.

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

## Arguments

This Action supports inputs from the user. These inputs are listed in the table below:

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

jobs:
  ecr-scan:
    runs-on: ubuntu-latest

    steps:
      # [Probably build and push image to ECR here]

      - name: Wait for ECR Scan and Get SARIF Report
        uses: sartography/github-actions-library/wait-for-ecr-scan-and-get-sarif@main
        with:
          repository_name: "infr/testcloud2202"
          image_tag: "main"
          aws_region: "us-east-2"
          output_file: "report.sarif"

      - name: Upload SARIF file
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: report.sarif
          category: security
```

## Tests

If changing the format of the output, remember to run the generate script to recreate the expected SARIF files.

```bash
./wait-for-ecr-scan-and-get-sarif/bin/generate_expected_sarif_files
```
