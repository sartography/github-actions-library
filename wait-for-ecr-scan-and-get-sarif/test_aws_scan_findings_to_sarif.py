import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from pylib.aws_scan_findings_to_sarif import convert_to_sarif


# these tests take response json from the AWS scan result API and run our code
# to convert them to sarif. the test then compares that result to a known good
# sarif output that we created manually and committed to this repo.
# so basically a regression test.


def test_convert_to_sarif_minimal_ecr_scan():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    sample_file_path = os.path.join(base_dir, "tests/ecr-scan-result-minimal.json")
    with open(sample_file_path, "r") as f:
        ecr_response = json.load(f)

    expected_output_file_path = os.path.join(
        base_dir, "tests/ecr-scan-result-minimal-expected-sarif.json"
    )
    with open(expected_output_file_path, "r") as f:
        expected_response = json.load(f)

    sarif_report = convert_to_sarif(ecr_response)
    assert sarif_report == expected_response


def test_convert_to_sarif_enhanced_ecr_scan():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    sample_file_path = os.path.join(base_dir, "tests/ecr-scan-result-ubuntu.json")
    with open(sample_file_path, "r") as f:
        ecr_response = json.load(f)

    expected_output_file_path = os.path.join(
        base_dir, "tests/ecr-scan-result-ubuntu-expected-sarif.json"
    )
    with open(expected_output_file_path, "r") as f:
        expected_response = json.load(f)

    sarif_report = convert_to_sarif(ecr_response)
    assert sarif_report == expected_response


def test_convert_to_sarif_when_no_findings():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    sample_file_path = os.path.join(base_dir, "tests/ecr-scan-result-no-findings.json")
    with open(sample_file_path, "r") as f:
        ecr_response = json.load(f)

    expected_output_file_path = os.path.join(
        base_dir, "tests/ecr-scan-result-no-findings-expected-sarif.json"
    )
    with open(expected_output_file_path, "r") as f:
        expected_response = json.load(f)

    sarif_report = convert_to_sarif(ecr_response)
    assert sarif_report == expected_response


def test_convert_to_sarif_with_cvss():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    sample_file_path = os.path.join(
        base_dir, "tests/ecr-scan-result-with-cvss-scores.json"
    )
    with open(sample_file_path, "r") as f:
        ecr_response = json.load(f)

    expected_output_file_path = os.path.join(
        base_dir, "tests/ecr-scan-result-with-cvss-scores-expected-sarif.json"
    )
    with open(expected_output_file_path, "r") as f:
        expected_response = json.load(f)

    sarif_report = convert_to_sarif(ecr_response)
    assert sarif_report == expected_response
