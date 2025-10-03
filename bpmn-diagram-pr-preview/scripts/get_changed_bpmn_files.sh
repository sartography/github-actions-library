#!/bin/bash

# This script identifies all added or modified BPMN files in a pull request
# and outputs their paths with status (A for added, M for modified), one per line.

BASE_SHA=$1
HEAD_SHA=$2

# Get the list of added (A) or modified (M) BPMN files with their status
# Using 'git diff --name-status --diff-filter=AM' to get file names with status
# and then filtering for files ending with .bpmn
CHANGED_BPMN_FILES=$(git diff --name-status --diff-filter=AM "$BASE_SHA" "$HEAD_SHA" | grep '\.bpmn$')

# Output the paths of the changed BPMN files with status, one per line
echo "$CHANGED_BPMN_FILES"
