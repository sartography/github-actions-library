# BPMN Diagram PR Preview GitHub Action

This action automatically generates visual previews of BPMN diagram changes in pull requests. It detects modified or added BPMN files, renders them as images, and posts the visual comparisons as PR comments.

## Usage

To integrate with your Actions pipeline, specify the name of this repository with a branch or tag number (`main` is recommended) as a `step` within your `workflow.yml` file.

**Important**: If you want to use the automatic PR comment feature (enabled by default), your **calling workflow** needs `pull-requests: write` permission. The action inherits permissions from the workflow that calls it.

Inside your `.github/workflows/workflow.yml` file:

```yaml
steps:
  - name: BPMN Diagram PR Preview
    uses: your-org/github-actions-library/bpmn-diagram-pr-preview@main
    with:
      base_sha: ${{ github.event.pull_request.base.sha }}
      head_sha: ${{ github.event.pull_request.head.sha }}
      image_store_api_key: "your-api-key-here"
      create_pr_comment: "true"  # Optional, defaults to true
```

## Arguments

This Action supports inputs from the user. These inputs are listed in the table below:

| Input              | Description                              |  Required  |
| :----------------- | :--------------------------------------- | :--------: |
| `base_sha`         | Base commit SHA for comparison           | \*Required |
| `head_sha`         | Head commit SHA for comparison           | \*Required |
| `image_store_api_key`| Image store API key | \*Required |
| `create_pr_comment`| Whether to create a PR comment with the rendered diagrams | Optional (default: `true`) |

## Permissions

When using the automatic PR comment feature (default behavior), your **calling workflow** needs the following permissions:

```yaml
permissions:
  contents: read        # Required for checking out code and reading files
  pull-requests: write  # Required for creating PR comments
```

If you disable PR comments by setting `create_pr_comment: "false"`, you only need:

```yaml
permissions:
  contents: read  # Only need read access
```

## Outputs

| Output          | Description                                                      |
| :-------------- | :--------------------------------------------------------------- |
| `uploaded_urls` | JSON object mapping BPMN file paths to their uploaded image URLs |

### Example full `workflow.yml` using this Action

```yaml
name: Show Diagram Changes

on:
  pull_request:
    paths:
      - "**.bpmn"

permissions:
  contents: read
  pull-requests: write  # Required for creating PR comments

jobs:
  render-bpmn:
    runs-on: ubuntu-latest
    steps:
      - name: Project setup
        uses: bpmn-io/actions/setup@latest

      - name: Checkout
        uses: actions/checkout@v5
        with:
          fetch-depth: 2

      - name: BPMN Diagram PR Preview
        uses: sartography/github-actions-library/bpmn-diagram-pr-preview@main
        with:
          base_sha: ${{ github.event.pull_request.base.sha }}
          head_sha: ${{ github.event.pull_request.head.sha }}
          image_store_api_key: "your-api-key-here"
          # create_pr_comment: "true"  # Optional, defaults to true
```

### Example with PR comment disabled

If you want to handle the PR comment creation yourself or disable it entirely (no special permissions needed):

```yaml
name: Show Diagram Changes

on:
  pull_request:
    paths:
      - "**.bpmn"

permissions:
  contents: read  # Only need read access when PR comments are disabled

jobs:
  render-bpmn:
    runs-on: ubuntu-latest
    steps:
      - name: Project setup
        uses: bpmn-io/actions/setup@latest

      - name: Checkout
        uses: actions/checkout@v5
        with:
          fetch-depth: 2

      - name: BPMN Diagram PR Preview
        id: render-diagrams
        uses: sartography/github-actions-library/bpmn-diagram-pr-preview@main
        with:
          base_sha: ${{ github.event.pull_request.base.sha }}
          head_sha: ${{ github.event.pull_request.head.sha }}
          image_store_api_key: "your-api-key-here"
          create_pr_comment: "false"

      # Now you can use ${{ steps.render-diagrams.outputs.uploaded_urls }} 
      # for custom processing if needed
```

## How it works

1. **File Detection**: Uses `git diff` to identify added or modified BPMN files between the base and head commits
2. **Content Retrieval**: Uses `git show` to get the file contents from both commits
3. **Image Rendering**: Converts BPMN files to PNG images using the `bpmn-to-image` library
4. **Upload**: Uploads the generated images to the specified image store API
5. **Output**: Returns a JSON mapping of file paths to their uploaded image URLs

The action handles both newly added files (where only the "after" image is generated) and modified files (where both "before" and "after" images are generated for comparison).
