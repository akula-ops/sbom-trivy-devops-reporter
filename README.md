# sbom-trivy-devops-reporter
Templates for automating SBOM generation and vulnerability scanning using Trivy in DevOps pipelines. The results are converted to JUnit XML format for seamless integration into DevOps test reporting, enabling efficient tracking and management of vulnerabilities.

#### Steps to add Trivy SBOM Generation and Vulnerability Scan to the DevOps Pipeline

1. **Add steps in DevOps Pipeline**:
   - Add the following stages to your `azure-pipelines.yaml` file:
     - **Install Trivy**: Installs Trivy and publishes it as a pipeline artifact.
     - **Generate SBOM**: Generates the SBOM file using Trivy and publishes it as a build artifact.
     - **Vulnerability Scan**: Scans for vulnerabilities using the SBOM file and converts the results to JUnit XML format for DevOps test reporting.
   - Place these stages before the final publishing stage.

#### Steps to Test Trivy SBOM Generation and Vulnerability Scan from Console

1. **Install Trivy Locally**:
   - Follow the [official Trivy installation guide](https://trivy.dev/latest/getting-started/installation/) to install Trivy on your local machine.

2. **Generate the SBOM File**:
   - Run the following command in the root of your project to generate the SBOM file in CycloneDX JSON format:
     ```bash
     trivy fs --format cyclonedx --output sbom.json .
     ```
   - This scans the root directory and outputs the SBOM to `sbom.json`.

3. **Run the Vulnerability Scan**:
   - Use the SBOM file to perform a vulnerability scan:
     ```bash
     trivy sbom --severity HIGH,CRITICAL --exit-code 0 --format json --output vulnerability-report.json sbom.json
     ```
   - This scans for vulnerabilities with `HIGH` and `CRITICAL` severity and outputs the results to `vulnerability-report.json`.

4. **Convert Vulnerability Report to JUnit XML**:
   - Install the required Python dependencies:
     ```bash
     pip install -r requirements.txt
     ```
    **Note**: If this is not a Python project, you still need to install the required libraries listed in the `requirements.txt` file to run the script. Ensure Python and `pip` are installed on your system.

    - In the DevOps pipeline, Python dependencies are installed using the following command:
     ```bash
     python3 -m pip install --upgrade pip
     python3 -m pip install -r $(System.DefaultWorkingDirectory)/scripts/requirements.txt
     ```
   **Note**: requirements needs to be installed for the output report in CLI to be generated. If you are not using the CLI, you can remove installation and remove generation of the CLI report form the script file.

   - Use the provided Python script to convert the vulnerability report into JUnit XML format:
     ```bash
     python convert_trivy_to_junit.py vulnerability-report.json vulnerability-report-tests.xml
     ```
   - This will create the file `vulnerability-report-tests.xml` with vulnerabilities converted into test cases for the DevOps Tests tab.
   - Additionally, it creates a table in the CLI summarizing the vulnerabilities.

5. **Publish Test Results (Pipeline Only)**:
   - In the DevOps pipeline, the JUnit XML report is published as test results using the `PublishTestResults@2` (adjust name based on your pipeline) task. This allows vulnerabilities to be displayed in the DevOps Tests tab.

**Notes**:
- The script processes vulnerabilities with `HIGH` and `CRITICAL` severities, but can be adjusted to include `MEDIUM` and `LOW` vulnerabilities.
- Ensure the input file is a valid JSON file and the output file has a `.xml` extension.
- Logs will provide feedback during execution, including errors for missing files or invalid JSON.
- For the best implementation consider creating template for the pipeline and use it in different projects.
