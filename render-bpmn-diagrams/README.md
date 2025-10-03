# Render BPMN Diagrams GitHub Action

This action renders BPMN diagrams for changed files in a pull request and uploads them to an image store. It's designed to automatically generate visual representations of BPMN files that have been added or modified in a PR.

## Usage

To integrate with your Actions pipeline, specify the name of this repository with a branch or tag number (`main` is recommended) as a `step` within your `workflow.yml` file.

Inside your `.github/workflows/workflow.yml` file:

```yaml
steps:
  - name: Render BPMN Diagrams
    uses: your-org/github-actions-library/render-bpmn-diagrams@main
    with:
      base_sha: ${{ github.event.pull_request.base.sha }}
      head_sha: ${{ github.event.pull_request.head.sha }}
```

## Arguments

This Action supports inputs from the user. These inputs are listed in the table below:

| Input      | Description                    |  Required  |
| :--------- | :----------------------------- | :--------: |
| `base_sha` | Base commit SHA for comparison | \*Required |
| `head_sha` | Head commit SHA for comparison | \*Required |

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

      - name: Render BPMN Diagrams
        id: render-diagrams
        uses: sartography/github-actions-library/render-bpmn-diagrams@main
        with:
          base_sha: ${{ github.event.pull_request.base.sha }}
          head_sha: ${{ github.event.pull_request.head.sha }}

      - name: Upload images as PR comment
        uses: actions/github-script@v6
        env:
          UPLOADED_URLS_JSON: ${{ steps.render-diagrams.outputs.uploaded_urls }}
        with:
          script: |
            console.log(`🕐 ${new Date().toISOString().replace('T', ' ').substring(0, 19)} - Starting PR comment creation`);
            const uploadedUrls = JSON.parse(process.env.UPLOADED_URLS_JSON || '{}'); // Handle empty JSON
            let commentBody = `## BPMN Diagram Changes\n\n`;

            if (Object.keys(uploadedUrls).length === 0) {
              commentBody += `_No BPMN diagrams were added or modified in this pull request._`;
            } else {
              // Separate files by status and sort alphabetically
              const addedFiles = [];
              const modifiedFiles = [];
              const errorFiles = [];

              for (const bpmnFilePath in uploadedUrls) {
                const fileData = uploadedUrls[bpmnFilePath];
                if (fileData.error) {
                  errorFiles.push(bpmnFilePath);
                } else if (fileData.status === 'A') {
                  addedFiles.push(bpmnFilePath);
                } else {
                  modifiedFiles.push(bpmnFilePath);
                }
              }

              // Sort all arrays alphabetically
              addedFiles.sort();
              modifiedFiles.sort();
              errorFiles.sort();

              // Process added files first
              if (addedFiles.length > 0) {
                commentBody += `### 📄 New Files\n\n`;
                for (const bpmnFilePath of addedFiles) {
                  const { afterUrl } = uploadedUrls[bpmnFilePath];
                  commentBody += `#### \`${bpmnFilePath}\`\n\n`;
                  commentBody += `![Diagram](${afterUrl})\n\n`;
                  commentBody += `---\n\n`;
                }
              }

              // Process modified files next
              if (modifiedFiles.length > 0) {
                commentBody += `### ✏️ Modified Files\n\n`;
                for (const bpmnFilePath of modifiedFiles) {
                  const { beforeUrl, afterUrl } = uploadedUrls[bpmnFilePath];
                  commentBody += `#### \`${bpmnFilePath}\`\n\n`;
                  if (beforeUrl) {
                    commentBody += `**Before**\n`;
                    commentBody += `![Before Diagram](${beforeUrl})\n\n`;
                    commentBody += `**After**\n`;
                    commentBody += `![After Diagram](${afterUrl})\n\n`;
                  } else {
                    commentBody += `![Diagram](${afterUrl})\n\n`;
                  }
                  commentBody += `---\n\n`;
                }
              }

              // Process error files last
              if (errorFiles.length > 0) {
                commentBody += `### ⚠️ Processing Errors\n\n`;
                for (const bpmnFilePath of errorFiles) {
                  const { error } = uploadedUrls[bpmnFilePath];
                  commentBody += `#### \`${bpmnFilePath}\`\n\n`;
                  commentBody += `_Error processing this file: ${error}_\n\n`;
                  commentBody += `---\n\n`;
                }
              }
            }

            console.log(`🕐 ${new Date().toISOString().replace('T', ' ').substring(0, 19)} - Creating GitHub comment`);
            await github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: commentBody
            });
            console.log(`🕐 ${new Date().toISOString().replace('T', ' ').substring(0, 19)} - Finished PR comment creation`);
```

## How it works

1. **File Detection**: Uses `git diff` to identify added or modified BPMN files between the base and head commits
2. **Content Retrieval**: Uses `git show` to get the file contents from both commits
3. **Image Rendering**: Converts BPMN files to PNG images using the `bpmn-to-image` library
4. **Upload**: Uploads the generated images to the specified image store API
5. **Output**: Returns a JSON mapping of file paths to their uploaded image URLs

The action handles both newly added files (where only the "after" image is generated) and modified files (where both "before" and "after" images are generated for comparison).
