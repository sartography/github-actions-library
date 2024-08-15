import argparse
from pylib.aws_scan_findings_to_sarif import convert_to_sarif

from pylib.wait_for_ecr_scan import get_image_scan_findings, wait_for_image_scan


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
    wait_for_image_scan(args.repository_name, args.image_tag, args.region)
    ecr_scan_result_file = get_image_scan_findings(
        args.repository_name, args.image_tag, args.region
    )
    convert_to_sarif(ecr_scan_result_file, args.output_file)


if __name__ == "__main__":
    main()
