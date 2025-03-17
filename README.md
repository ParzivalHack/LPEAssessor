# LPEAssessor: Linux Privilege Escalation Assessment Tool
![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Python](https://img.shields.io/badge/Python-3.6%2B-blue)

![image](https://github.com/user-attachments/assets/344b6d8b-bb1c-4882-8f63-3c2020942560)


LPEAssessor is a comprehensive Linux privilege escalation assessment tool designed for security professionals, system administrators, and penetration testers. It systematically identifies potential privilege escalation vectors, verifies their exploitability, and provides detailed reports with actionable remediation recommendations.

## Features

- **Comprehensive Scanning**: Detects 17+ types of privilege escalation vulnerabilities
- **Real-time Verification**: Verifies vulnerabilities to minimize false positives
- **Advanced Exploitation**: Generates practical exploitation commands with multiple approaches, including comprehensive GTFOBins techniques for SUID/SGID binaries
- **Path Hijacking Analysis**: Sophisticated path manipulation vulnerability detection
- **Intelligent Monitoring**: Optional monitoring for privileged execution of hijacked binaries
- **Professional Reporting**: Generates detailed HTML, JSON, and text reports
- **Threading Support**: Multithreaded scanning for improved performance
- **System Compatibility**: Works across various Linux distributions

## Installation

```bash
# Clone the repository
git clone https://github.com/ParzivalHack/LPEAssessor.git
cd LPEAssessor
```

# Usage

```
# Basic scan with default options
python LPEAssessor.py

# Generate a report in all formats (HTML, JSON, text)
python LPEAssessor.py -o report

# Verbose output with custom log file
python LPEAssessor.py -v -l assessment.log

# Increase number of scanning threads
python LPEAssessor.py -t 20

# Skip information gathering and exploit generation
python LPEAssessor.py --skip-info --skip-exploits

# Monitor for successful path hijacking exploits
python LPEAssessor.py --monitor-only --monitor-timeout 600
```

### Command-line Options

```markdown
| Option | Description |
|--------|-------------|
| `-o, --output` | Output file for the report (without extension) |
| `-f, --format` | Report format: json, text, html, or all (default: all) |
| `-v, --verbose` | Enable verbose output |
| `-l, --log` | Log file path |
| `-t, --threads` | Number of threads to use for scanning (default: 10) |
| `-u, --username` | Specify a username for exploit generation (default: current user) |
| `--timeout` | Timeout for scans in seconds (default: 3600) |
| `--skip-exploits` | Skip exploit generation |
| `--skip-info` | Skip system information gathering |
| `--skip-report` | Skip report generation |
| `--monitor-only` | Only monitor for successful path hijacking exploits |
| `--monitor-timeout` | Timeout for monitoring in seconds (default: 300) |
| `--verify none|safe|full` | Choose verification mode (default: safe) |
| `--verify-timeout SECONDS` | Set timeout for verification attempts (default: 10) |
```

## Example Report

[Real HTML Report Example](https://parzivalhack.github.io/LPEAssessor/examplereport.html)

[Real JSON Report Example](https://github.com/ParzivalHack/LPEAssessor/blob/main/examplereport.json)

[Real TXT Report Example](https://github.com/ParzivalHack/LPEAssessor/blob/main/examplereport.txt)

## Supported Vulnerability Types

- SUID Binary Exploitation
- SGID Binary Exploitation
- Writable Files Owned by Root
- World-Writable Directories
- Weak File Permissions
- Docker Group Membership
- Plaintext Credentials
- Kernel Exploits
- Writable Cron Jobs
- Sudo Permissions
- Exposed Internal Services
- PATH Hijacking Vulnerabilities

## Compliance Support

LPEAssessor helps organizations meet security assessment requirements for several compliance frameworks, including:

- NIST SP 800-53 (Security Control RA-5: Vulnerability Scanning)
- CIS Controls (Control 3: Continuous Vulnerability Management)
- PCI DSS (Requirement 11.2: Regular Vulnerability Scanning)
- ISO 27001 (Control A.12.6.1: Management of Technical Vulnerabilities)

The detailed reports generated by LPEAssessor provide documentation that can be used as evidence during compliance audits and security assessments.

## Legal Disclaimer

This tool is provided for educational and professional security assessment purposes only. Usage of LPEAssessor for attacking targets without prior mutual consent is illegal. The developers are not responsible for any misuse or damage caused by this program.

**Use responsibly and only on systems you have permission to test.**

A full disclaimer can be found [here](https://github.com/ParzivalHack/LPEAssessor/blob/main/DISCLAIMER.md)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [MIT LICENSE](LICENSE) file for details. 
