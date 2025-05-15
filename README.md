# Lookout CVE Reporter

A Python tool for fetching and reporting devices vulnerable to specific CVEs from the Lookout Mobile Endpoint Protection API.

## Features

- **Dual Interface**: Run as a command-line tool or with a graphical user interface
- **CVE Filtering**: Search for devices vulnerable to specific CVEs
- **Platform Filtering**: Filter results by platform (iOS or Android)
- **OS Version Filtering**: Filter results by specific OS versions
- **CSV Export**: Export results to CSV for further analysis
- **Detailed Device Information**: View comprehensive device details including email, customer ID, model, and security patch level

## Prerequisites

- Python 3.6+
- A valid Lookout Application Key from the Lookout Mobile Endpoint Protection Console

## Installation

1. Clone this repository:
   ```
   git clone git@github.com:fgravato/lookoutcve.git
   cd lookout-mes-cve-reporter
   ```

2. Install required dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Create a `.env` file in the project root directory with your Lookout Application Key:
   ```
   LOOKOUT_APPLICATION_KEY="YOUR_LOOKOUT_APPLICATION_KEY_HERE"
   # Optional: Specify a default output filename
   # DEFAULT_OUTPUT_FILENAME="vulnerable_devices.csv"
   ```

## Usage

### Command Line Interface

```
python lookout_cve_reporter.py --cve CVE-YYYY-XXXXX [--platform ios|android] [--os-version VERSION] [--output FILENAME.csv]
```

Arguments:
- `--cve`: (Required) The CVE ID to search for (e.g., CVE-2023-12345)
- `--platform`: (Optional) Filter by platform (ios or android)
- `--os-version`: (Optional) Filter by OS version (exact match)
- `--output`: (Optional) Output CSV filename (default: vulnerable_devices.csv)
- `--gui`: (Optional) Launch in GUI mode

### Graphical User Interface

```
python lookout_cve_reporter.py --gui
```

Or simply run without arguments to launch the GUI:

```
python lookout_cve_reporter.py
```

## API Endpoints Used

- Authentication: `https://api.lookout.com/oauth2/token`
- OS Vulnerabilities: `https://api.lookout.com/mra/api/v2/os-vulns/devices`
- Device Details: `https://api.lookout.com/mra/api/v2/device`

## Output Format

The CSV output includes the following columns:
- GUID
- Email
- Customer Device ID
- Platform
- Device Model
- OS Version
- Latest OS Version
- Security Patch Level

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.