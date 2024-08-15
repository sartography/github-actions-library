import json
import argparse
from pylib.aws_scan_findings_to_sarif import convert_to_sarif

from pylib.wait_for_ecr_scan import wait_for_image_scan


def main():
    parser = argparse.ArgumentParser(
        description="Wait for ECR scan and then convert it to a sarif report."
    )
    parser.add_argument(
        "--repository_name",
        required=True,
        help="The repository name",
    )
    parser.add_argument("--image_tag", required=True, help="The image tag.")
    parser.add_argument("--aws_region", required=True, help="The aws region.")
    parser.add_argument("--output_file", required=True, help="The output SARIF file.")

    args = parser.parse_args()
    ecr_scan_result = wait_for_image_scan(
        args.repository_name, args.image_tag, args.aws_region
    )
    sarif_report = convert_to_sarif(ecr_scan_result)

    with open(args.output_file, "w") as f:
        json.dump(sarif_report, f, indent=2)


if __name__ == "__main__":
    main()
