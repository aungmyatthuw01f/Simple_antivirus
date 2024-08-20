from flask import Flask, request, render_template, jsonify
import os
import hashlib
import requests
import json
from requests.exceptions import ConnectionError
import time

app = Flask(__name__)
API_KEY = 'Your_API_KEY'

@app.route('/')
def index():
    return render_template('index.html')

def get_file_report(resource, retries=3, delay=5):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': API_KEY, 'resource': resource}
    for attempt in range(retries):
        try:
            response = requests.get(url, params=params)
            response.raise_for_status()
            if response.text.strip():
                return response.json()
            else:
                return {'error': 'No content returned from VirusTotal', 'status': 'no_content'}
        except (requests.exceptions.HTTPError, json.JSONDecodeError):
            return {'error': 'Failed to decode JSON or HTTP error', 'status': 'api_error'}
        except ConnectionError:
            if attempt < retries - 1:
                time.sleep(delay)
                continue
            return {'error': 'Failed to resolve domain name', 'status': 'dns_error'}
    return {'error': 'Max retries exceeded', 'status': 'retry_exceeded'}

def upload_file(filepath):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    with open(filepath, 'rb') as file:
        files = {'file': (os.path.basename(filepath), file)}
        params = {'apikey': API_KEY}
        response = requests.post(url, files=files, params=params)
        if response.ok:
            upload_response = response.json()
            return upload_response.get('resource')
    return None

def wait_for_report(resource, max_attempts=10):
    attempts = 0
    while attempts < max_attempts:
        result = get_file_report(resource)
        if result and result.get('response_code') == 1:
            return result
        time.sleep(10)
        attempts += 1
    return {'error': 'Timeout or maximum attempts exceeded waiting for report'}

def scan_file(filepath, detailed):
    file_size = os.path.getsize(filepath)
    if file_size > 5242880:
        return {'error': 'File exceeds the 5 MB size limit and was not uploaded.'}

    hasher = hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    file_hash = hasher.hexdigest()
    result = get_file_report(file_hash)

    if not result or result.get('status') in ['no_content', 'http_error', 'json_error'] or result.get('response_code') == 0:
        resource = upload_file(filepath)
        if resource:
            result = wait_for_report(resource)

    if result and result.get('response_code') == 1:
        response_data = {
            'message': 'Malware detected' if result.get('positives', 0) > 0 else 'No malware detected',
            'positives': result.get('positives', 0),
            'total': result.get('total', 0),
            'filename': os.path.basename(filepath)
        }
        if detailed:
            response_data.update({
                'scan_date': result.get('scan_date'),
                'scans': result.get('scans')
            })
        return response_data
    return {'message': 'File processed', 'filename': os.path.basename(filepath), 'detailed': detailed}

@app.route('/upload', methods=['POST'])
def handle_upload():
    files = request.files.getlist('file')
    detailed = request.form.get('detailed') == 'on'
    results = []
    
    save_dir = 'temp_storage'
    if not os.path.exists(save_dir):
        os.makedirs(save_dir)
    
    for file in files:
        filepath = os.path.join(save_dir, file.filename)
        file.save(filepath)
        result = scan_file(filepath, detailed)
        result['filename'] = file.filename
        os.remove(filepath)
        results.append(result)
    
    return jsonify(results)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
