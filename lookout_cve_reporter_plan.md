# Lookout CVE Reporter Tool: Development Plan (Revised)

**I. Introduction & Goal**
The primary goal is to develop a Python command-line tool (`lookout_cve_reporter.py`) that fetches a list of devices vulnerable to a specific CVE from the Lookout API. The tool will allow optional filtering by platform (iOS/Android) and OS version (exact match), and then export the filtered list to a CSV file.

**II. Prerequisites**
1.  A valid **Lookout Application Key** obtained from the Lookout Mobile Endpoint Protection Console.
2.  Python 3.x installed.
3.  Required Python libraries: `requests` (for HTTP calls) and `python-dotenv` (for managing environment variables). These can be installed via pip.

**III. Project Setup**
1.  **Directory Structure:**
    Create a directory named `lookout-cve-reporter/`.
2.  **Script File:**
    Inside `lookout-cve-reporter/`, the main script will be named `lookout_cve_reporter.py`.
3.  **Configuration File (`.env`):**
    Inside the `lookout-cve-reporter/` directory, a file named `.env` will store sensitive and configuration data:
    ```env
    LOOKOUT_APPLICATION_KEY="YOUR_LOOKOUT_APPLICATION_KEY_HERE"
    # Optional: Specify a default output filename
    # DEFAULT_OUTPUT_FILENAME="vulnerable_devices.csv"
    ```
4.  **Requirements File (optional but recommended):**
    A `requirements.txt` file can list dependencies:
    ```
    requests
    python-dotenv
    ```

**IV. Core Logic & Workflow (Python Implementation)**

The `lookout_cve_reporter.py` script will perform the following steps:

1.  **Import Libraries:**
    ```python
    import os
    import csv
    import argparse
    import requests
    from dotenv import load_dotenv
    ```

2.  **Load Configuration:**
    *   Use `load_dotenv()` to load variables from the `.env` file.
    *   Access `LOOKOUT_APPLICATION_KEY = os.getenv("LOOKOUT_APPLICATION_KEY")`.
    *   Access `DEFAULT_OUTPUT_FILENAME = os.getenv("DEFAULT_OUTPUT_FILENAME")`.

3.  **Parse Command-Line Arguments:**
    *   Use the `argparse` module.
    *   `parser.add_argument("--cve", required=True, help="CVE ID (e.g., CVE-2023-12345)")`
    *   `parser.add_argument("--platform", choices=["ios", "android"], help="Filter by platform (iOS or Android)")`
    *   `parser.add_argument("--os-version", help="Filter by OS version (exact match)")`
    *   `parser.add_argument("--output", help="Output CSV filename")`

4.  **Authenticate with Lookout API:**
    *   Define a function, e.g., `get_lookout_access_token(api_key)`.
    *   `token_url = "https://api.lookout.com/oauth2/token"`
    *   `headers = {"Content-Type": "application/x-www-form-urlencoded", "Authorization": f"Bearer {api_key}"}`
    *   `data = {"grant_type": "client_credentials"}`
    *   Make a `requests.post()` call.
    *   Handle response and extract `access_token`.

5.  **Fetch Vulnerable Devices:**
    *   Define a function, e.g., `fetch_vulnerable_devices(access_token, cve_id)`.
    *   `devices_url = "https://api.lookout.com/mra/api/v2/os-vulns/devices"`
    *   `headers = {"Authorization": f"Bearer {access_token}"}`
    *   `params = {"name": cve_id}`
    *   Make a `requests.get()` call.
    *   Handle response and return the list of devices (from the `devices` key in the JSON response).

6.  **Filter Devices (Locally):**
    *   Define a function, e.g., `filter_devices(devices, platform_filter, os_version_filter)`.
    *   Iterate through the devices.
    *   If `platform_filter` is provided:
        *   `if device.get("platform", "").lower() == platform_filter.lower():` (using `.get()` for safety)
    *   If `os_version_filter` is provided:
        *   `if device.get("os_version") == os_version_filter:` (exact match)
    *   Return the filtered list.

7.  **Export to CSV:**
    *   Define a function, e.g., `export_to_csv(devices, filename)`.
    *   Determine output filename (CLI > .env > default "vulnerable_devices.csv").
    *   Use the `csv` module.
    *   **CSV Columns:** `guid`, `platform`, `os_version`, `latest_os_version`, `security_patch_level`.
    *   Write headers and then device data.

8.  **Main Execution Block:**
    ```python
    if __name__ == "__main__":
        # Load .env
        # Parse args
        # Validate LOOKOUT_APPLICATION_KEY
        # Get access token
        # Fetch devices
        # Filter devices
        # Determine output filename
        # Export to CSV
        # Print success/error messages
    ```

**V. Error Handling**
Implement `try-except` blocks for:
*   Missing `LOOKOUT_APPLICATION_KEY`.
*   Network errors during API calls (`requests.exceptions.RequestException`).
*   HTTP errors (checking `response.status_code`).
*   JSON decoding errors.
*   File I/O errors for CSV writing.
*   Informative messages if no devices are found or if filters result in an empty list.

**VI. Conceptual Workflow Diagram (Unchanged)**

```mermaid
graph TD
    A[Start] --> B{Read .env Config};
    B --> C[Parse CLI Arguments: CVE, Filters, Output File];
    C --> D{LOOKOUT_APPLICATION_KEY present?};
    D -- No --> E[Exit with Error: Missing Key];
    D -- Yes --> F[Authenticate with Lookout API to get Access Token];
    F --> G{Authentication Successful?};
    G -- No --> H[Exit with Error: Auth Failed];
    G -- Yes --> I[Store Access Token];
    I --> J[Fetch Vulnerable Devices by CVE from /mra/api/v2/os-vulns/devices];
    J --> K{API Request Successful?};
    K -- No --> L[Exit with Error: API Fetch Failed];
    K -- Yes --> M[Parse Device List from API Response];
    M --> N[Apply Local Filters (Platform, OS Version if provided)];
    N --> O[Prepare Filtered Device Data for CSV];
    O --> P[Determine Output CSV Filename];
    P --> Q[Write Data to CSV File];
    Q --> R{CSV Write Successful?};
    R -- No --> S[Exit with Error: CSV Write Failed];
    R -- Yes --> T[End - Success];
    E --> U[End];
    H --> U;
    L --> U;
    S --> U;