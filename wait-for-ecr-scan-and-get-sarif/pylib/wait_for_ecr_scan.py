import json
import boto3
import time
import sys


# def wait_for_image_scan(repository_name, image_tag, region):
#     client = boto3.client("ecr", region_name=region)
#
#     while True:
#         response = client.describe_images(
#             repositoryName=repository_name, imageIds=[{"imageTag": image_tag}]
#         )
#
#         print(f"➡️ ➡️ ➡️  response: {response}")
#         status = response["imageDetails"][0]["imageScanStatus"]["status"]
#         print(f"Scan status: {status}")
#
#         if status == "COMPLETE":
#             break
#         elif status == "FAILED":
#             raise Exception("Scan failed to complete")
#         else:
#             print("Still scanning, waiting for 30 seconds...")
#             time.sleep(30)


def wait_for_image_scan(repository_name, image_tag, region):
    client = boto3.client("ecr", region_name=region)
    response = None

    while True:
        # maybe just check if this raises or not
        response = client.describe_image_scan_findings(
            repositoryName=repository_name, imageId={"imageTag": image_tag}
        )

        if "imageScanFindings" in response:
            print("HIHIHI")
        findings = response.get("imageScanFindings", {}).get("findings", [])
        findings += response.get("imageScanFindings", {}).get("enhancedFindings", [])
        print(f"Found {len(findings)} issues.")

        if len(findings) > 0:
            break

        print("Still scanning, waiting for 30 seconds...")
        time.sleep(30)
        # scan_status = response.get("imageScanStatus", {}).get("status")
        #
        # if not scan_status:
        #     print(f"No image scan status found for tag: {image_tag}")
        #     sys.exit(1)
        #
        # print(f"Scan status: {scan_status}")
        #
        # if scan_status == "COMPLETE":
        #     print("Image scan complete!")
        #     break
        # elif scan_status == "FAILED":
        #     print("Image scan failed!")
        #     sys.exit(1)
        # else:

    return response


if __name__ == "__main__":
    repository_name = sys.argv[1]
    image_tag = sys.argv[2]
    region = sys.argv[3]

    wait_for_image_scan(repository_name, image_tag, region)
