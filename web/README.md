# Malware File Scanner

## Overview
This web application provides a user-friendly interface to upload and scan files for malware using the VirusTotal API. It allows users to upload multiple files, check each file's hash against VirusTotal's database, upload new files for scanning, and display detailed scan results.

## Features
- **Multiple File Upload** Users can select and upload multiple files simultaneously.
- **Asynchronous Scanning** Each file is processed sequentially to avoid overloading the server and to handle API rate limits effectively.
- **Detailed Scan Reports** Users can opt to receive detailed information about the scan results, including which malware signatures were detected by which antivirus engines.
- **Responsive UI** The application includes a loading indicator that shows the progress of file uploads and scans, enhancing the user experience.
- **Error Handling** Robust error handling to manage DNS issues, API errors, and file size limitations.

## Installation

### Prerequisites
- Python 3.6 or higher
- Flask
- Requests


### Install Dependencies
```bash
pip install -r requirements.txt
```

### Setting Up API Key
Obtain an API key from VirusTotal and set it in your environment variables or directly in the application
```bash
export API_KEY='your_api_key_here'
```

## Running the Application
```bash
python app.py
```
This will start the server on `http//127.0.0.5000/` by default. Visit this URL in a web browser to use the application.

## Using the Application
- Navigate to the home page and use the "Choose File" button to select files you want to scan.
- Check the "Detailed Report" box if you want detailed information about the scans.
- Click "Scan" to submit the files for scanning. The results will be displayed on the same page under the form.

## Functions
- `get_file_report(resource)` Retrieves the scan report for a given resource (file hash) from VirusTotal.
- `upload_file(filepath)` Uploads a file to VirusTotal for scanning and returns the unique resource identifier.
- `wait_for_report(resource)` Polls VirusTotal for the scanning report of a given resource until the report is available or a timeout occurs.
- `scan_file(filepath, detailed)` Handles the scanning process for a single file, including checking, uploading, and waiting for the scan report.
- `handle_upload()` Manages the file upload process from the web form, processes each file, and returns the scanning results.

## License
This project is open-sourced under the MIT License. See the LICENSE file for more details.
