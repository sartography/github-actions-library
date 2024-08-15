import json
import argparse
import jsonschema


def convert_to_sarif(ecr_response):
    sarif_report = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AWS ECR",
                        "informationUri": "https://aws.amazon.com/ecr/",
                        "rules": [],
                    }
                },
                "results": [],
            }
        ],
    }

    def process_findings(findings, is_enhanced=False):
        for finding in findings:
            # make sure severity is an accepted value
            # aws likes to use things lke "untriaged"
            severity = finding["severity"]
            severity_for_level = severity
            if severity_for_level.lower() not in ["none", "note", "warning", "error"]:
                severity_map = {
                    "untriaged": "none",
                    "low": "note",
                    "medium": "warning",
                    "high": "error",
                    "critical": "error",
                }
                severity_for_level = severity_map.get(
                    severity_for_level.lower(), "none"
                )

            if is_enhanced:
                vulnerability_id = finding["packageVulnerabilityDetails"][
                    "vulnerabilityId"
                ]
                source_url = finding["packageVulnerabilityDetails"]["sourceUrl"]
                vulnerable_packages = finding["packageVulnerabilityDetails"][
                    "vulnerablePackages"
                ]
                cvss = finding["packageVulnerabilityDetails"]["cvss"]
                base_score = None
                if len(cvss) > 0:
                    base_score = cvss[0]["baseScore"]

                rule = {
                    "id": vulnerability_id,
                    "name": "OsPackageVulnerability",
                    "shortDescription": {"text": finding["description"]},
                    "fullDescription": {"text": finding["description"]},
                    "defaultConfiguration": {"level": severity_for_level},
                    "helpUri": source_url,
                    "help": {
                        "text": f"Vulnerability {vulnerability_id}\nSeverity: {severity}\nPackage: {vulnerable_packages[0]['name']}\nFixed Version: \nLink: [{vulnerability_id}]({source_url})",
                        "markdown": f"**Vulnerability {vulnerability_id}**\n| Severity | Package | Fixed Version | Link |\n| --- | --- | --- | --- |\n|{severity}|{vulnerable_packages[0]['name']}||[{vulnerability_id}]({source_url})\n\n{finding['description']}",
                    },
                    "properties": {
                        "precision": "very-high",
                        "security-severity": base_score,
                        "tags": [
                            "vulnerability",
                            "security",
                            severity,
                        ],
                    },
                }
                result = {
                    "ruleId": vulnerability_id,
                    "ruleIndex": len(
                        sarif_report["runs"][0]["tool"]["driver"]["rules"]
                    ),
                    "level": severity_for_level,
                    "message": {
                        "text": f"Package: {vulnerable_packages[0]['name']}\nInstalled Version: {vulnerable_packages[0]['version']}\nVulnerability {vulnerability_id}\nSeverity: {severity}\nFixed Version: \nLink: [{vulnerability_id}]({source_url})"
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": ecr_response["repositoryName"],
                                    "uriBaseId": "ROOTPATH",
                                },
                                "region": {
                                    "startLine": 1,
                                    "startColumn": 1,
                                    "endLine": 1,
                                    "endColumn": 1,
                                },
                            },
                            "message": {
                                "text": f"{ecr_response['repositoryName']}: {vulnerable_packages[0]['name']}@{vulnerable_packages[0]['version']}"
                            },
                        }
                    ],
                }
            else:
                rule = {
                    "id": finding["name"],
                    "name": "OsPackageVulnerability",
                    "shortDescription": {"text": finding["description"]},
                    "fullDescription": {"text": finding["description"]},
                    "defaultConfiguration": {"level": severity_for_level},
                    "helpUri": finding["uri"],
                    "help": {
                        "text": f"Vulnerability {finding['name']}\nSeverity: {severity}\nPackage: {finding['attributes'][1]['value']}\nFixed Version: \nLink: [{finding['name']}]({finding['uri']})",
                        "markdown": f"**Vulnerability {finding['name']}**\n| Severity | Package | Fixed Version | Link |\n| --- | --- | --- | --- |\n|{severity}|{finding['attributes'][1]['value']}||[{finding['name']}]({finding['uri']})\n\n{finding['description']}",
                    },
                    "properties": {
                        "precision": "very-high",
                        "security-severity": finding["attributes"][3]["value"],
                        "tags": ["vulnerability", "security", severity],
                    },
                }
                result = {
                    "ruleId": finding["name"],
                    "ruleIndex": len(
                        sarif_report["runs"][0]["tool"]["driver"]["rules"]
                    ),
                    "level": severity_for_level,
                    "message": {
                        "text": f"Package: {finding['attributes'][1]['value']}\nInstalled Version: {finding['attributes'][0]['value']}\nVulnerability {finding['name']}\nSeverity: {severity}\nFixed Version: \nLink: [{finding['name']}]({finding['uri']})"
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": ecr_response["repositoryName"],
                                    "uriBaseId": "ROOTPATH",
                                },
                                "region": {
                                    "startLine": 1,
                                    "startColumn": 1,
                                    "endLine": 1,
                                    "endColumn": 1,
                                },
                            },
                            "message": {
                                "text": f"{ecr_response['repositoryName']}: {finding['attributes'][1]['value']}@{finding['attributes'][0]['value']}"
                            },
                        }
                    ],
                }
            sarif_report["runs"][0]["tool"]["driver"]["rules"].append(rule)
            sarif_report["runs"][0]["results"].append(result)

    if (
        "imageScanFindings" in ecr_response
        and "findings" in ecr_response["imageScanFindings"]
    ):
        process_findings(ecr_response["imageScanFindings"]["findings"])

    if (
        "imageScanFindings" in ecr_response
        and "enhancedFindings" in ecr_response["imageScanFindings"]
    ):
        process_findings(
            ecr_response["imageScanFindings"]["enhancedFindings"], is_enhanced=True
        )

    return sarif_report


# hack. python's validator doesn't like the regex in the sarif schema. use a slightly simpler regex to validate language.
def update_schema_patterns(schema):
    if isinstance(schema, dict):
        # If the schema is a dictionary, check each key-value pair
        for key, value in schema.items():
            if key == "pattern" and value == "^(?i)[a-zA]{2}(-[a-z]{2})?$":
                # Replace the pattern with the simplified version
                schema[key] = "^[a-zA-Z]{2}(-[a-zA-Z]{2})?$"
            else:
                # Recursively update nested dictionaries or lists
                update_schema_patterns(value)
    elif isinstance(schema, list):
        # If the schema is a list, update each item
        for item in schema:
            update_schema_patterns(item)


def main():
    def load_sarif_schema(schema_path):
        with open(schema_path, "r") as f:
            return json.load(f)

    def validate_sarif(sarif_report, schema):
        update_schema_patterns(schema)

        try:
            jsonschema.validate(instance=sarif_report, schema=schema)
            print("SARIF report is valid.")
        except jsonschema.ValidationError as e:
            print(f"SARIF report is invalid: {e.message}")

    parser = argparse.ArgumentParser(
        description="Convert ECR scan findings to SARIF format."
    )
    parser.add_argument(
        "--input_file",
        required=True,
        help="The input JSON file with ECR scan findings.",
    )
    parser.add_argument("--output_file", required=True, help="The output SARIF file.")
    SCHEMA_FILE_PATH = "./wait-for-ecr-scan-and-get-sarif/sarif-schema-2.1.0.json"
    args = parser.parse_args()

    sarif_schema = load_sarif_schema(SCHEMA_FILE_PATH)

    with open(args.input_file, "r") as f:
        ecr_response = json.load(f)

    sarif_report = convert_to_sarif(ecr_response)

    with open(args.output_file, "w") as f:
        json.dump(sarif_report, f, indent=2)

    validate_sarif(sarif_report, sarif_schema)


if __name__ == "__main__":
    main()
