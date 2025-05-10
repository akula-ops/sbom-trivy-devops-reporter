"""Convert Trivy vulnerability reports from JSON to JUnit XML format."""
import json
import os
import xml.etree.ElementTree as ET
import logging
import argparse

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

def convert_trivy_to_junit(input_file_json: str, output_file_xml: str) -> None:
    """
    Converts a Trivy vulnerability report from JSON format to JUnit XML format.

    Args:
        input_file_json (str): Path to the Trivy JSON report.
        output_file_xml (str): Path to save the JUnit XML report.
    """
    if not os.path.exists(input_file_json):
        logger.error(f"Input file '{input_file_json}' does not exist.")
        raise FileNotFoundError(f"Input file '{input_file_json}' does not exist.")

    try:
        # Load the Trivy JSON report
        with open(input_file_json, 'r') as json_vuln_file:
            report = json.load(json_vuln_file)
    except FileNotFoundError:
        logger.error(f"The file '{input_file_json}' was not found.")
        raise
    except json.JSONDecodeError:
        logger.error(f"Failed to parse JSON from '{input_file_json}'.")
        raise

    # Extract vulnerabilities from the report
    vulnerabilities = []
    for result in report.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            vulnerabilities.append(vuln)
    if not vulnerabilities:
        logger.info("No vulnerabilities found in the input file.")
        return

    # Create the JUnit XML structure
    testsuites = ET.Element("testsuites")
    testsuite = ET.SubElement(
        testsuites,
        "testsuite",
        name="Vulnerability Scan",
        tests=str(len(vulnerabilities)),
        failures=str(len(vulnerabilities))
    )

    # Add each vulnerability as a test case
    for vuln in vulnerabilities:
        testcase = ET.SubElement(
            testsuite,
            "testcase",
            classname="Trivy",
            name=f"{vuln.get('Severity', 'Unknown')} - {vuln.get('PkgName', 'Unknown')}@{vuln.get('InstalledVersion', 'Unknown')} - ({vuln['VulnerabilityID']})"
        )
        failure = ET.SubElement(
            testcase,
            "failure",
            message=(
                f"Vulnerability found: {vuln['Severity']} severity in {vuln['PkgName']}@{vuln['InstalledVersion']} "
                f"({vuln['VulnerabilityID']}). Fixed in version: {vuln.get('FixedVersion', 'N/A')}. "
                f"Status: {vuln.get('Status', 'unknown')}."
            )
        )
        failure.text = f"{vuln.get('Severity', 'Unknown')}: {vuln.get('Title', 'No Title')} ({vuln.get('VulnerabilityID', 'Unknown')})"

    tree = ET.ElementTree(testsuites)
    tree.write(output_file_xml)
    logger.info(f"{len(vulnerabilities)} vulnerabilities found. JUnit XML report successfully written to '{output_file_xml}'.")

def main():
    """
    Command-line interface for the Trivy to JUnit XML converter.
    """
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Convert Trivy JSON reports to JUnit XML format.")
    parser.add_argument("input_file", type=str, help="Path to the Trivy JSON report.")
    parser.add_argument("output_file", type=str, help="Path to save the JUnit XML report.")
    args = parser.parse_args()

    # Validate file extensions
    if not args.input_file.endswith('.json'):
        logger.error("Input file must have a .json extension.")
        exit(1)
    if not args.output_file.endswith('.xml'):
        logger.error("Output file must have a .xml extension.")
        exit(1)

    # Run the conversion
    try:
        convert_trivy_to_junit(args.input_file, args.output_file)
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        exit(1)

if __name__ == "__main__":
    main()
