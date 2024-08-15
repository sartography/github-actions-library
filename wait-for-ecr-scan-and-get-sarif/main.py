import json
import time
import argparse

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
                        "rules": []
                    }
                },
                "results": []
            }
        ]
    }

    findings = ecr_response["imageScanFindings"]["findings"]
    for finding in findings:
        rule = {
            "id": finding["name"],
            "name": "OsPackageVulnerability",
            "shortDescription": {
                "text": finding["description"]
            },
            "fullDescription": {
                "text": finding["description"]
            },
            "defaultConfiguration": {
                "level": finding["severity"].lower()
            },
            "helpUri": finding["uri"],
            "help": {
                "text": f"Vulnerability {finding['name']}\nSeverity: {finding['severity']}\nPackage: {finding['attributes'][1]['value']}\nFixed Version: \nLink: [{finding['name']}]({finding['uri']})",
                "markdown": f"**Vulnerability {finding['name']}**\n| Severity | Package | Fixed Version | Link |\n| --- | --- | --- | --- |\n|{finding['severity']}|{finding['attributes'][1]['value']}||[{finding['name']}]({finding['uri']})\n\n{finding['description']}"
            },
            "properties": {
                "precision": "very-high",
                "security-severity": finding["attributes"][3]["value"],
                "tags": [
                    "vulnerability",
                    "security",
                    finding["severity"]
                ]
            }
        }
        sarif_report["runs"][0]["tool"]["driver"]["rules"].append(rule)

        result = {
            "ruleId": finding["name"],
            "ruleIndex": len(sarif_report["runs"][0]["tool"]["driver"]["rules"]) - 1,
            "level": finding["severity"].lower(),
            "message": {
                "text": f"Package: {finding['attributes'][1]['value']}\nInstalled Version: {finding['attributes'][0]['value']}\nVulnerability {finding['name']}\nSeverity: {finding['severity']}\nFixed Version: \nLink: [{finding['name']}]({finding['uri']})"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": "library/ubuntu",
                            "uriBaseId": "ROOTPATH"
                        },
                        "region": {
                            "startLine": 1,
                            "startColumn": 1,
                            "endLine": 1,
                            "endColumn": 1
                        }
                    },
                    "message": {
                        "text": f"library/ubuntu: {finding['attributes'][1]['value']}@{finding['attributes'][0]['value']}"
                    }
                }
            ]
        }
        sarif_report["runs"][0]["results"].append(result)

    return sarif_report

def main():
    parser = argparse.ArgumentParser(description="Convert ECR scan findings to SARIF format.")
    parser.add_argument("--input_file", required=True, help="The input JSON file with ECR scan findings.")
    parser.add_argument("--output_file", required=True, help="The output SARIF file.")
    args = parser.parse_args()

    with open(args.input_file, "r") as f:
        ecr_response = json.load(f)

    sarif_report = convert_to_sarif(ecr_response)

    with open(args.output_file, "w") as f:
        json.dump(sarif_report, f, indent=2)

if __name__ == "__main__":
    main()
