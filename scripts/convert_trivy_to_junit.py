"""Convert Trivy vulnerability reports from JSON to JUnit XML format."""
import json
import os
import xml.etree.ElementTree as ET
import logging
import argparse
from tabulate import tabulate

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

def truncate_text(input_text: str, length: int=50) -> str:
    """Truncate text to a fixed length with ellipsis if needed.
    
    Args: 
        text (str): string to be truncated
        length (int): length of the text

    Returns: 
        text (str): truncated text with added ellipsis if the text was too long    
    """
    return input_text if len(input_text) <= length else input_text[:length - 3] + "..."

def convert_trivy_to_junit(vuln_input_json: str, vulnerability_xml_report: str) -> None:
    """
    Converts a Trivy vulnerability report from JSON format to JUnit XML format.
    Output also CLI table with vulnerabilities summary.

    Args:
        vuln_input_json (str): Path to the Trivy JSON report.
        vulnerability_xml_report (str): Path to save the JUnit XML report.
    Raises:
        FileNotFoundError: If the input JSON file does not exist.
        json.JSONDecodeError: If the JSON file cannot be parsed.
    """
    if not os.path.exists(vuln_input_json):
        logger.error(f"Input file '{vuln_input_json}' does not exist.")
        raise FileNotFoundError(f"Input file '{vuln_input_json}' does not exist.")

    try:
        # Load the Trivy JSON report
        with open(vuln_input_json, 'r') as json_vuln_file:
            report = json.load(json_vuln_file)
    except FileNotFoundError:
        logger.error(f"The file '{vuln_input_json}' was not found.")
        raise
    except json.JSONDecodeError:
        logger.error(f"Failed to parse JSON from '{vuln_input_json}'.")
        raise

    # Extract vulnerabilities from the report if not extracted then return logger info
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

    # Print vulnerabilities summary table for CLI
    # Different information can be added to the table if needed,
    # based on the requirements and available data.
    for vuln in vulnerabilities:
        testcase = ET.SubElement(
            testsuite,
            "testcase",
            classname="Trivy",
            # Test name that will be shown in the Tests tab in Azure DevOps
            name=f"{vuln.get('Severity', 'Unknown')} - {vuln.get('PkgName', 'Unknown')}@{vuln.get('InstalledVersion', 'Unknown')} - ({vuln['VulnerabilityID']})"
        )
        failure = ET.SubElement(
            testcase,
            "failure",
            # Description that will be shown in the Tests tab in Azure DevOps for each test when opened
            message=(
                f"Vulnerability found: {vuln['Severity']} severity in {vuln['PkgName']}@{vuln['InstalledVersion']} "
                f"({vuln['VulnerabilityID']}). Fixed in version: {vuln.get('FixedVersion', 'N/A')}. "
                f"Status: {vuln.get('Status', 'unknown')}."
            )
        )
        failure.text = f"{vuln.get('Severity', 'Unknown')}: {vuln.get('Title', 'No Title')} ({vuln.get('VulnerabilityID', 'Unknown')})"

    tree = ET.ElementTree(testsuites)
    tree.write(vulnerability_xml_report)
    logger.info(f"{len(vulnerabilities)} vulnerabilities found. JUnit XML report successfully written to '{vulnerability_xml_report}'.")
    
    # Print vulnerabilities summary table for CLI
    # Different information can be added to the table if needed,
    # based on the requirements and available data.
    table_data = []
    for vuln in vulnerabilities:
        table_data.append([
            vuln.get('Severity', 'Unknown'),
            vuln.get('PkgName', 'Unknown'),
            vuln.get('VulnerabilityID', 'Unknown'),
            truncate_text(vuln.get('Title', 'No description available'), length=50),
            vuln.get('FixedVersion', 'N/A')
        ])

    headers = ["Severity", "Package", "CVE", "Description", "Fixed Version"]
    print("\nVulnerabilities Summary:")
    print(tabulate(table_data, headers=headers, tablefmt="grid"))

def main() -> None:
    """Command-line interface for the Trivy to JUnit XML converter."""
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Convert Trivy JSON reports to JUnit XML format.")
    parser.add_argument("vuln_input_json", type=str, help="Path to the Trivy JSON report.")
    parser.add_argument("vulnerability_xml_report", type=str, help="Path to save the JUnit XML report.")
    args = parser.parse_args()

    # Validate file extensions before running the conversion
    if not args.vuln_input_json.endswith('.json'):
        logger.error("Input file must have a .json extension.")
        exit(1)
    if not args.vulnerability_xml_report.endswith('.xml'):
        logger.error("Output file must have a .xml extension.")
        exit(1)

    # Run the conversion
    try:
        convert_trivy_to_junit(args.vuln_input_json, args.vulnerability_xml_report)
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        exit(1)

if __name__ == "__main__":
    main()
