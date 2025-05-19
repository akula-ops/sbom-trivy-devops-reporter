"""Basic unit tests for the convert_trivy_to_junit script."""

import os
import json
import pytest
from xml.etree.ElementTree import parse
from scripts.convert_trivy_to_junit import convert_trivy_to_junit

@pytest.fixture
def files_fixture():
    """Fixture to create temporary input and output files for testing purposes."""
    vulnerability_input = "vulnerability_input_temp.json"
    vulnerability_output = "vulnerability_output_temp.xml"
    yield vulnerability_input, vulnerability_output
    if os.path.exists(vulnerability_input):
        os.remove(vulnerability_input)
    if os.path.exists(vulnerability_output):
        os.remove(vulnerability_output)

def test_conversion_with_valid_data(files_fixture):
    """Ensure the function correctly converts a valid Trivy JSON report."""
    vulnerability_input, vulnerability_output = files_fixture

    # Sample Trivy JSON report with one vulnerability
    sample_report = {
        "Results": [
            {
                "Vulnerabilities": [
                    {
                        "Severity": "HIGH",
                        "PkgName": "test-package",
                        "InstalledVersion": "2.0.0",
                        "VulnerabilityID": "CVE-2023-12345",
                        "FixedVersion": "2.1.0",
                        "Title": "Sample Vulnerability",
                        "Status": "unfixed"
                    }
                ]
            }
        ]
    }
    with open(vulnerability_input, "w") as file:
        json.dump(sample_report, file)

    convert_trivy_to_junit(vulnerability_input, vulnerability_output)

    assert os.path.exists(vulnerability_output)
    tree = parse(vulnerability_output)
    root = tree.getroot()
    assert root.tag == "testsuites"
    # Has one testsuite element meaning that the conversion was successful
    assert len(root.findall(".//testcase")) == 1

def test_conversion_with_empty_results(files_fixture):
    """Check behavior when the input JSON has no vulnerabilities."""
    vulnerability_input, vulnerability_output = files_fixture

    empty_report = {"Results": []}
    with open(vulnerability_input, "w") as f:
        json.dump(empty_report, f)

    convert_trivy_to_junit(vulnerability_input, vulnerability_output)

    assert not os.path.exists(vulnerability_output)

def test_missing_vulnerability_input(files_fixture):
    """Verify the function raises an error when the input file is missing."""
    _, vulnerability_output = files_fixture

    with pytest.raises(FileNotFoundError):
        convert_trivy_to_junit("nonexistent_input_file.json", vulnerability_output)

def test_invalid_json_format(files_fixture):
    """Test the function with an invalid JSON file."""
    vulnerability_input, vulnerability_output = files_fixture

    with open(vulnerability_input, "w") as f:
        f.write("{invalid_json}")

    with pytest.raises(json.JSONDecodeError):
        convert_trivy_to_junit(vulnerability_input, vulnerability_output)

