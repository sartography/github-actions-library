import json
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

    def process_findings(findings, is_enhanced=False):
        for finding in findings:
            if is_enhanced:
                rule = {
                    "id": finding["vulnerabilityId"],
                    "name": "OsPackageVulnerability",
                    "shortDescription": {
                        "text": finding["description"]
                    },
                    "fullDescription": {
                        "text": finding["description"]
                    },
                    "defaultConfiguration": {
                        "level": finding["vendorSeverity"].lower()
                    },
                    "helpUri": finding["sourceUrl"],
                    "help": {
                        "text": f"Vulnerability {finding['vulnerabilityId']}\nSeverity: {finding['vendorSeverity']}\nPackage: {finding['vulnerablePackages'][0]['name']}\nFixed Version: \nLink: [{finding['vulnerabilityId']}]({finding['sourceUrl']})",
                        "markdown": f"**Vulnerability {finding['vulnerabilityId']}**\n| Severity | Package | Fixed Version | Link |\n| --- | --- | --- | --- |\n|{finding['vendorSeverity']}|{finding['vulnerablePackages'][0]['name']}||[{finding['vulnerabilityId']}]({finding['sourceUrl']})\n\n{finding['description']}"
                    },
                    "properties": {
                        "precision": "very-high",
                        "security-severity": finding["cvss"][0]["baseScore"],
                        "tags": [
                            "vulnerability",
                            "security",
                            finding["vendorSeverity"]
                        ]
                    }
                }
                result = {
                    "ruleId": finding["vulnerabilityId"],
                    "ruleIndex": len(sarif_report["runs"][0]["tool"]["driver"]["rules"]),
                    "level": finding["vendorSeverity"].lower(),
                    "message": {
                        "text": f"Package: {finding['vulnerablePackages'][0]['name']}\nInstalled Version: {finding['vulnerablePackages'][0]['version']}\nVulnerability {finding['vulnerabilityId']}\nSeverity: {finding['vendorSeverity']}\nFixed Version: \nLink: [{finding['vulnerabilityId']}]({finding['sourceUrl']})"
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": ecr_response["repositoryName"],
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
                                "text": f"{ecr_response['repositoryName']}: {finding['vulnerablePackages'][0]['name']}@{finding['vulnerablePackages'][0]['version']}"
                            }
                        }
                    ]
                }
            else:
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
                result = {
                    "ruleId": finding["name"],
                    "ruleIndex": len(sarif_report["runs"][0]["tool"]["driver"]["rules"]),
                    "level": finding["severity"].lower(),
                    "message": {
                        "text": f"Package: {finding['attributes'][1]['value']}\nInstalled Version: {finding['attributes'][0]['value']}\nVulnerability {finding['name']}\nSeverity: {finding['severity']}\nFixed Version: \nLink: [{finding['name']}]({finding['uri']})"
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": ecr_response["repositoryName"],
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
                                "text": f"{ecr_response['repositoryName']}: {finding['attributes'][1]['value']}@{finding['attributes'][0]['value']}"
                            }
                        }
                    ]
                }
            sarif_report["runs"][0]["tool"]["driver"]["rules"].append(rule)
            sarif_report["runs"][0]["results"].append(result)

    if "imageScanFindings" in ecr_response and "findings" in ecr_response["imageScanFindings"]:
        process_findings(ecr_response["imageScanFindings"]["findings"])

    if "enhancedFindings" in ecr_response:
        process_findings(ecr_response["enhancedFindings"], is_enhanced=True)

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
