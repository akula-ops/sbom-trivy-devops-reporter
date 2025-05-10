# sbom-trivy-devops-reporter
DevOps pipeline templates for generating SBOMs and scanning vulnerabilities using Trivy, with results integrated into DevOps test reporting.

#### Steps to Test Trivy SBOM Generation and  Vulnerability Scan from console

1. **Install Trivy Locally**:
   - Follow the [official Trivy installation guide](https://trivy.dev/latest/getting-started/installation/) to install Trivy on your local machine.

2. **Generate the SBOM File**:
   - Run the following command in the root of your project to generate the SBOM file in CycloneDX JSON format:
     ```bash
     trivy fs --format cyclonedx --output sbom.json .
     ```
   - This scans the root directory and outputs the SBOM to sbom.json.

3. **Run the Vulnerability Scan**:
   - Use the SBOM file to perform a vulnerability scan:
     ```bash
     trivy sbom --severity HIGH,CRITICAL --exit-code 0 --format json --output vulnerability-report.json sbom.json
     ```
   - This scans for vulnerabilities with `HIGH` and `CRITICAL` severity and outputs the results to vulnerability-report.json.

4. **Convert Vulnerability Report to JUnit XML**:
   - Use the provided Python script to convert the vulnerability report into JUnit XML format:
     ```bash
     python pipelines/scripts/convert_trivy_to_junit.py vulnerability-report.json vulnerability-report-tests.xml
     ```
   - This will create file `vulnerability-report-tests.xml` with vulnerabilities converted into test cases for DevOps Tests tab.
