import json
import pytest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from aws_scan_findings_to_sarif import convert_to_sarif


def test_convert_to_sarif():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    sample_file_path = os.path.join(
        base_dir, "tests/sample-api-response-ecr-describe-image-scan-findings.json"
    )
    with open(sample_file_path, "r") as f:
        ecr_response = json.load(f)

    sarif_report = convert_to_sarif(ecr_response)

    assert sarif_report["version"] == "2.1.0"
    assert sarif_report["runs"][0]["tool"]["driver"]["name"] == "AWS ECR"
    assert len(sarif_report["runs"][0]["results"]) == 1
    assert sarif_report["runs"][0]["results"][0]["ruleId"] == "CVE-2019-5188"
    assert sarif_report["runs"][0]["results"][0]["level"] == "warning"


# def test_convert_to_sarif_reduced_to_one_issue():
#     base_dir = os.path.dirname(os.path.abspath(__file__))
#     sample_file_path = os.path.join(base_dir, "tests/sample-api-response-ecr-scan-ubuntu-reduced-to-one-issue.json")
#     expected_output_path = os.path.join(base_dir, "tests/trivy-report-ubuntu-reduced-to-one-issue.sarif")
#
#     with open(sample_file_path, "r") as f:
#         ecr_response = json.load(f)
#     with open(expected_output_path, "r") as f:
#         expected_output = json.load(f)
#
#     sarif_report = convert_to_sarif(ecr_response)
#
#     assert sarif_report == expected_output
