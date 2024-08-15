import json
import boto3
import time
import sys
from botocore.exceptions import ClientError


def wait_for_image_scan(repository_name, image_tag, region):
    client = boto3.client("ecr", region_name=region)
    response = None

    max_retries = 10
    retries = 0

    while retries < max_retries:
        # maybe just check if this raises or not
        try:
            response = client.describe_image_scan_findings(
                repositoryName=repository_name, imageId={"imageTag": image_tag}
            )
        except ClientError as e:
            if e.response['Error']['Code'] == 'ScanNotFoundException':
                print(f"Scan not found for tag: {image_tag}. Retrying...")
                retries += 1
                time.sleep(30)
                continue
            else:
                raise

        if "imageScanFindings" in response:
            print(f"Scan found for repository {repository_name} and tag {image_tag}")
            break

        # findings = response.get("imageScanFindings", {}).get("findings", [])
        # findings += response.get("imageScanFindings", {}).get("enhancedFindings", [])
        # print(f"Found {len(findings)} issues.")
        #
        # if len(findings) > 0:
        #     break

        print("Still scanning, waiting for 30 seconds...")
        time.sleep(30)
        retries += 1

    if retries == max_retries:
        raise Exception("Max retries reached. Scan not found or incomplete.")
    else:
        return response


if __name__ == "__main__":
    repository_name = sys.argv[1]
    image_tag = sys.argv[2]
    region = sys.argv[3]

    wait_for_image_scan(repository_name, image_tag, region)
