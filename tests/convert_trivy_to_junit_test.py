import os
import json
import pytest
from xml.etree.ElementTree import parse
from scripts.convert_trivy_to_junit import convert_trivy_to_junit

@pytest.fixture
def temp_files():
    """Fixture to create temporary input and output files for testing."""
    input_file = "temp_input.json"
    output_file = "temp_output.xml"
    yield input_file, output_file
    if os.path.exists(input_file):
        os.remove(input_file)
    if os.path.exists(output_file):
        os.remove(output_file)

def test_conversion_with_valid_data(temp_files):
    """Ensure the function correctly converts a valid Trivy JSON report."""
    input_file, output_file = temp_files

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
    with open(input_file, "w") as f:
        json.dump(sample_report, f)

    # Run the conversion
    convert_trivy_to_junit(input_file, output_file)

    # Check if the output file exists and validate its content
    assert os.path.exists(output_file)
    tree = parse(output_file)
    root = tree.getroot()
    assert root.tag == "testsuites"
    assert len(root.findall(".//testcase")) == 1

def test_conversion_with_empty_results(temp_files):
    """Check behavior when the input JSON has no vulnerabilities."""
    input_file, output_file = temp_files

    empty_report = {"Results": []}
    with open(input_file, "w") as f:
        json.dump(empty_report, f)

    # Run the conversion
    convert_trivy_to_junit(input_file, output_file)

    # Ensure no output file is created
    assert not os.path.exists(output_file)

def test_missing_input_file(temp_files):
    """Verify the function raises an error when the input file is missing."""
    _, output_file = temp_files

    with pytest.raises(FileNotFoundError):
        convert_trivy_to_junit("nonexistent_file.json", output_file)

def test_invalid_json_format(temp_files):
    """Test the function with an invalid JSON file."""
    input_file, output_file = temp_files

    # Write invalid JSON to the input file
    with open(input_file, "w") as f:
        f.write("{invalid_json}")

    with pytest.raises(json.JSONDecodeError):
        convert_trivy_to_junit(input_file, output_file)

