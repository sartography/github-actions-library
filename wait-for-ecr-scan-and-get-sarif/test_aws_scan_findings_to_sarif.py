import json
import pytest
from aws_scan_findings_to_sarif import convert_to_sarif

def test_convert_to_sarif():
    with open("sample-api-response-ecr-describe-image-scan-findings.json", "r") as f:
        ecr_response = json.load(f)

    sarif_report = convert_to_sarif(ecr_response)

    assert sarif_report["version"] == "2.1.0"
    assert sarif_report["runs"][0]["tool"]["driver"]["name"] == "AWS ECR"
    assert len(sarif_report["runs"][0]["results"]) == 1
    assert sarif_report["runs"][0]["results"][0]["ruleId"] == "CVE-2019-5188"
    assert sarif_report["runs"][0]["results"][0]["level"] == "medium"
