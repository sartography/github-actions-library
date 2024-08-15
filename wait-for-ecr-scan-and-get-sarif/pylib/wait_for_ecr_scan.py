import boto3
import time
import sys


def wait_for_image_scan(repository_name, image_tag, region):
    client = boto3.client("ecr", region_name=region)

    while True:
        response = client.describe_images(
            repositoryName=repository_name, imageIds=[{"imageTag": image_tag}]
        )

        status = response["imageDetails"][0]["imageScanStatus"]["status"]
        print(f"Scan status: {status}")

        if status == "COMPLETE":
            print("Image scan complete!")
            break
        elif status == "FAILED":
            print("Image scan failed!")
            sys.exit(1)
        else:
            print("Still scanning, waiting for 30 seconds...")
            time.sleep(30)


def get_image_scan_findings(repository_name, image_tag, region):
    client = boto3.client("ecr", region_name=region)

    response = client.describe_image_scan_findings(
        repositoryName=repository_name, imageId={"imageTag": image_tag}
    )

    findings = response.get("imageScanFindings", {}).get("findings", [])
    print(f"Found {len(findings)} issues.")

    for finding in findings:
        severity = finding.get("severity", "UNKNOWN")
        name = finding.get("name", "Unnamed finding")
        description = finding.get("description", "No description")
        print(f"- [{severity}] {name}: {description}")


if __name__ == "__main__":
    repository_name = sys.argv[1]
    image_tag = sys.argv[2]
    region = sys.argv[3]

    wait_for_image_scan(repository_name, image_tag, region)
    get_image_scan_findings(repository_name, image_tag, region)
