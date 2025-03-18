# DisHost

A powerful and flexible IP range scanner with configurable health checks.

[![Python](https://img.shields.io/badge/Python-3.6+-blue.svg)](https://www.python.org/downloads/) [![License](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

## Overview

DisHost (Discovery + Host) is a command-line tool written in Python that scans IP ranges and performs various health checks. It's designed to be versatile, efficient, and user-friendly, providing flexible configuration options and multiple output formats.

## Features

- **Flexible IP Range Specification**:
  - CIDR notation (e.g., `192.168.1.0/24`)
  - Start-End IP range (e.g., `10.0.0.1` to `10.0.0.254`)

- **Multiple Health Check Types**:
  - **ICMP**: Basic ping test
  - **TCP**: Port connectivity test
  - **HTTP/HTTPS**: Web service health checks with extensive configuration options

- **HTTP/HTTPS Check Options**:
  - Custom URL paths
  - HTTP method selection
  - Custom headers
  - Expected status code verification
  - Response content validation

- **Efficient Performance**:
  - Multi-threaded scanning
  - Configurable timeout values
  - Progress bar visualization

- **Output Options**:
  - Terminal display with color-coded results
  - JSON export
  - CSV export

## Installation

### Prerequisites

- Python 3.6 or higher
- pip (Python package manager)

### Setup

1. Clone the repository or download the script:

    ```bash
    git clone https://github.com/sammwyy/dishost.git
    # or just download dishost.py
    ```

2. Install required packages:

    ```bash
    pip install requests rich
    ```

3. Make the script executable (Linux/macOS):

    ```bash
    chmod +x dishost.py
    ```

## Usage

### Basic Syntax

```bash
python dishost.py [IP Range Options] [Health Check Options] [Output Options]
```

### IP Range Options (Required)

You must use either CIDR notation or start-end range:

- `--cidr CIDR`: Specify IP range in CIDR notation (e.g., `192.168.1.0/24`)
- `--start IP` and `--end IP`: Specify start and end IP addresses (e.g., `--start 1.1.1.0 --end 1.1.2.5`)

### Health Check Options

- `--check {icmp,tcp,http,https}`: Health check type (default: `icmp`)
- `--port PORT`: Port number for TCP/HTTP/HTTPS checks
- `--timeout SECONDS`: Connection timeout in seconds (default: `1.0`)
- `--count COUNT`: Number of ping packets for ICMP check (default: `1`)

### HTTP/HTTPS Specific Options

- `--path PATH`: URL path (default: `/`)
- `--method METHOD`: HTTP method (default: `GET`)
- `--headers HEADERS`: HTTP headers in format "Key1:Value1,Key2:Value2"
- `--expect-code CODE`: Expected HTTP status code (default: `200`)
- `--expect-text TEXT`: Text that should be in the HTTP response

### Output Options

- `--json FILENAME`: Save results to JSON file
- `--csv FILENAME`: Save results to CSV file
- `--no-progress`: Hide progress bar
- `--threads COUNT`: Maximum number of threads (default: `50`)

### Examples

#### ICMP (Ping) Check

```bash
# Scan a CIDR range with ICMP
python dishost.py --cidr 192.168.1.0/24 --check icmp

# Scan with 3 ping packets and 2-second timeout
python dishost.py --cidr 10.0.0.0/24 --check icmp --count 3 --timeout 2.0
```

#### TCP Port Check

```bash
# Check if SSH (port 22) is accessible
python dishost.py --start 10.0.0.1 --end 10.0.0.10 --check tcp --port 22

# Check for open SMTP ports with longer timeout
python dishost.py --cidr 192.168.1.0/24 --check tcp --port 25 --timeout 3.0
```

#### HTTP/HTTPS Check

```bash
# Basic HTTP check
python dishost.py --cidr 192.168.1.0/24 --check http --port 80

# Check a specific health endpoint
python dishost.py --cidr 10.0.0.0/24 --check http --port 8080 --path /health

# Check HTTPS with custom headers and expected response text
python dishost.py --cidr 172.16.0.0/16 --check https --port 443 \
  --path /api/status --method GET \
  --headers "Authorization:Bearer token123,Accept:application/json" \
  --expect-code 200 --expect-text "status\":\"UP"
```

#### Output Options examples

```bash
# Save results to files
python dishost.py --cidr 192.168.1.0/24 --check icmp --json results.json --csv results.csv

# Use more threads for faster scanning
python dishost.py --cidr 10.0.0.0/16 --check tcp --port 80 --threads 100
```

## Output Format

### Terminal Output

The terminal output includes:

- Scan summary (total, up, down)
- Detailed results for each IP
- Color-coded status indicators (green for up, red for down)

Example:

```bash
Scan Summary
Total IPs scanned: 254
UP: 12 | DOWN: 242 | Other: 0

Detailed Results:
IP: 192.168.1.1 | Status: up | Protocol: icmp | latency: 1.25ms
IP: 192.168.1.2 | Status: up | Protocol: icmp | latency: 2.34ms
...
```

### JSON Output

The JSON output includes:

- Metadata (timestamp, counts)
- Detailed results for each IP

Example structure:

```json
{
  "metadata": {
    "timestamp": "2025-03-17T14:30:22.123456",
    "total_hosts": 254,
    "up_hosts": 12,
    "down_hosts": 242
  },
  "results": [
    {
      "ip": "192.168.1.1",
      "protocol": "icmp",
      "status": "up",
      "latency": 1.25
    },
    ...
  ]
}
```

### CSV Output

CSV output contains all fields from the scan results, with one row per IP.

## Architecture

DisHost follows an object-oriented design with these main components:

- **HealthChecker**: Base class for health checks with protocol-specific subclasses
- **IPScanner**: Handles IP generation and parallel scanning
- **ResultManager**: Manages output display and file saving

## Troubleshooting

### Common Issues

1. **Permission errors**: When using ICMP checks, you may need elevated privileges:

   ```bash
   # On Linux/macOS
   sudo python dishost.py --cidr 192.168.1.0/24 --check icmp
   
   # On Windows (run as Administrator)
   ```

2. **Firewall restrictions**: Ensure your firewall allows outgoing ICMP/TCP/HTTP traffic.

3. **Rate limiting**: Some networks or hosts may rate-limit ping requests. Try increasing the timeout or reducing threads.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

- [Rich](https://github.com/Textualize/rich) - For terminal formatting and progress bars
- [Requests](https://requests.readthedocs.io/) - For HTTP/HTTPS functionality
