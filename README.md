# Network-Open-Port-Scanner-Tool
A fast, multithreaded Python port scanner that detects open ports on a target host, grabs service banners, and provides basic vulnerability hints based on common service ports and banner analysis.

# Fast Multithreaded Port Scanner with Basic Vulnerability Hints

This Python tool performs a fast and efficient port scan on a target host using multithreading. It scans a user-specified port range, detects open ports, grabs service banners, and provides basic vulnerability hints based on the port number and banner content.

## Features

- Multithreaded scanning for speed and efficiency (default 100 threads).
- Banner grabbing on open ports to identify running services.
- Basic vulnerability hints for common services (e.g., FTP, SSH, HTTP).
- Supports scanning by URL or IP address.
- Simple and easy-to-understand output with vulnerability warnings.

## Installation

1. Clone this repository:
https://github.com/RavinduLakshanMalawalaArachchi/Network-Open-Port-Scanner-Tool.git


2. Ensure you have Python 3 installed (tested on Python 3.7+).

3. Install any dependencies (standard library only, no external packages required).

## Usage

Run the script and follow the prompts:



You will be asked to enter:

- Target URL or hostname (e.g., `http://example.com` or `192.168.1.1`)
- Start port number (e.g., `1`)
- End port number (e.g., `1024`)

The scanner will then perform a fast scan and print open ports, banners, and vulnerability hints.

## Disclaimer

This tool is intended for educational and authorized security testing purposes only. Always obtain explicit permission before scanning any network or host.

## License

[MIT License](LICENSE)

## Contributions

Contributions and improvements are welcome! Feel free to open issues or submit pull requests.

---



