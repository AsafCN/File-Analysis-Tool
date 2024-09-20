# File Analysis Tool

This is a Python-based tool that allows users to analyze files for malware, extract readable text, and detect the programming language used. It provides a simple graphical interface to select and analyze files with ease.

## Features

- **VirusTotal Integration**: Scan files using VirusTotal by calculating their SHA-256 hash and retrieving the malware report.
- **String Extraction**: Extract readable ASCII strings from binary files.
- **Programming Language Detection**: Analyze the extracted strings to identify the programming language or framework used.
- **File Type Identification**: Detect the type of the file (e.g., Windows EXE, Linux ELF, macOS Mach-O).
- **Simple GUI**: Built with `customtkinter`, the tool offers an easy-to-use interface for selecting and analyzing files.
- **Logging**: All actions and results are logged for later reference.

## Requirements

- Python 3.x
- `requests` library for interacting with VirusTotal API.
- `customtkinter` for the graphical user interface.
- VirusTotal API Key (replace the placeholder in the code).

Install the required dependencies:

```bash
pip install requests customtkinter
