#!/usr/bin/env python3
import subprocess
import sys
import os
import json
import csv
from datetime import datetime
import html

def setup_output_dir():
    """Create output directory with timestamp"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    #output_dir = f"output_{timestamp}"
    output_dir = f"output"
    os.makedirs(output_dir, exist_ok=True)
    return output_dir

def run_subfinder(domain, output_dir):
    """Run subfinder and save results"""
    subdomains_file = f"{output_dir}/{domain}_subdomains.txt"
    print(f"[+] Running subfinder against {domain}")
    subprocess.run([
        "subfinder",
        "-silent",
        "-d", domain,
        "-o", subdomains_file
    ])
    return subdomains_file

def run_httpx(subdomains_file, output_dir, domain):
    """Run httpx against discovered subdomains"""
    httpx_output = f"{output_dir}/{domain}_live_hosts.txt"
    print("[+] Running httpx to identify live web services")
    subprocess.run([
        "httpx",
        "-l", subdomains_file,
        "-silent",
        "-o", httpx_output
    ])
    return httpx_output

def run_nuclei(hosts_file, domain):
    """Run nuclei scan against live hosts"""
    print("[+] Running nuclei scan")
    output_dir = os.path.dirname(hosts_file)
    json_output = f"{output_dir}/{domain}_nuclei_results.json"
    
    # Run nuclei with JSON output
    try:
        # Create an empty JSON file first
        with open(json_output, 'w') as f:
            pass
        
        result = subprocess.run([
            "nuclei",
            "-l", hosts_file,
            "-json-export", json_output
        ], capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"[!] Error running nuclei: {result.stderr}")
            return None
        
        # Check if the file exists and has content
        if os.path.exists(json_output) and os.path.getsize(json_output) > 0:
            return json_output
        else:
            print("[!] No vulnerabilities found or nuclei output is empty")
            # Create a default JSON entry for empty results
            with open(json_output, 'w') as f:
                default_entry = {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "template-id": "none",
                    "info": {
                        "severity": "info",
                        "name": "No vulnerabilities found",
                        "description": "The nuclei scan completed successfully but found no vulnerabilities."
                    },
                    "host": "none",
                    "matched-at": "none"
                }
                f.write(json.dumps(default_entry))
            return json_output
            
    except Exception as e:
        print(f"[!] Error during nuclei scan: {str(e)}")
        return None

def convert_nuclei_to_csv(json_file, domain):
    """Convert nuclei JSON output to CSV"""
    output_dir = os.path.dirname(json_file)
    csv_file = f"{output_dir}/{domain}_nuclei_results.csv"
    
    print("[+] Converting nuclei results to CSV")
    
    # CSV headers
    headers = ['timestamp', 'template-id', 'info.severity', 'host', 'matched-at', 'info.name', 'info.description']
    
    with open(csv_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers)
        writer.writeheader()
        
        # Read the entire JSON file
        with open(json_file, 'r') as jsonfile:
            try:
                # Try to load the entire file as JSON
                json_content = json.load(jsonfile)
                
                # If it's a list, process each item
                if isinstance(json_content, list):
                    findings = json_content
                else:
                    # If it's a single object, wrap it in a list
                    findings = [json_content]
                
                for finding in findings:
                    try:
                        row = {
                            'timestamp': finding.get('timestamp', ''),
                            'template-id': finding.get('template-id', ''),
                            'info.severity': finding.get('info', {}).get('severity', ''),
                            'host': finding.get('host', ''),
                            'matched-at': finding.get('matched-at', ''),
                            'info.name': finding.get('info', {}).get('name', ''),
                            'info.description': finding.get('info', {}).get('description', '')
                        }
                        writer.writerow(row)
                    except AttributeError:
                        print(f"[!] Error processing finding: {finding}")
                        continue
                    
            except json.JSONDecodeError:
                # If the file isn't valid JSON, try reading line by line
                print("[!] Could not parse file as single JSON, trying line by line...")
                jsonfile.seek(0)  # Reset file pointer to beginning
                for line in jsonfile:
                    try:
                        finding = json.loads(line)
                        row = {
                            'timestamp': finding.get('timestamp', ''),
                            'template-id': finding.get('template-id', ''),
                            'info.severity': finding.get('info', {}).get('severity', ''),
                            'host': finding.get('host', ''),
                            'matched-at': finding.get('matched-at', ''),
                            'info.name': finding.get('info', {}).get('name', ''),
                            'info.description': finding.get('info', {}).get('description', '')
                        }
                        writer.writerow(row)
                    except (json.JSONDecodeError, AttributeError) as e:
                        print(f"[!] Error processing line: {line.strip()}")
                        continue
    
    print(f"[+] CSV file created: {csv_file}")
    return csv_file

def generate_html_report(json_file, output_dir, live_hosts_file, target_domain):
    """Generate a user-friendly HTML report from nuclei results"""
    html_file = f"{output_dir}/{target_domain}_nuclei_report.html"
    
    # Copy CSS file to output directory
    template_dir = os.path.join(os.path.dirname(__file__), 'templates')
    css_src = os.path.join(template_dir, 'styles.css')
    css_dst = os.path.join(output_dir, 'styles.css')
    try:
        with open(css_src, 'r') as src, open(css_dst, 'w') as dst:
            dst.write(src.read())
    except FileNotFoundError:
        print("[!] Warning: Could not copy CSS file")
    
    # Load HTML template
    template_path = os.path.join(template_dir, 'report_template.html')
    try:
        with open(template_path, 'r') as f:
            html_template = f.read()
    except FileNotFoundError:
        print("[!] Error: HTML template file not found")
        return None
    
    # Load live hosts
    try:
        with open(live_hosts_file, 'r') as f:
            web_services = [line.strip() for line in f if line.strip()]
        web_services_count = len(web_services)
        web_services_html = '\n'.join([f'<li>{service}</li>' for service in web_services])
    except FileNotFoundError:
        print("[!] Warning: Live hosts file not found")
        web_services_count = 0
        web_services_html = '<li>No web services found</li>'
    
    severity_colors = {
        'critical': '#e74c3c',
        'high': '#e67e22',
        'medium': '#f1c40f',
        'low': '#3498db',
        'info': '#2ecc71'
    }
    
    findings_html = []
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    
    print("[+] Generating HTML report")
    
    # Process JSON file
    with open(json_file, 'r') as f:
        try:
            # Try to load the entire file as JSON
            json_content = json.load(f)
            
            # If it's a list, process each item
            if isinstance(json_content, list):
                findings = json_content
            else:
                # If it's a single object, wrap it in a list
                findings = [json_content]
                
            for finding in findings:
                try:
                    severity = finding.get('info', {}).get('severity', 'info').lower()
                    severity_counts[severity] += 1
                    
                    finding_html = f"""
                    <div class="finding {severity}">
                        <div class="severity-badge" style="background-color: {severity_colors.get(severity, '#2ecc71')}">
                            {severity.upper()}
                        </div>
                        <h3>{html.escape(finding.get('info', {}).get('name', 'Unknown'))}</h3>
                        <p><strong>Host:</strong> {html.escape(finding.get('host', 'N/A'))}</p>
                        <p><strong>Matched At:</strong> {html.escape(finding.get('matched-at', 'N/A'))}</p>
                        <p><strong>Description:</strong> {html.escape(finding.get('info', {}).get('description', 'N/A'))}</p>
                        <div class="timestamp">Discovered: {finding.get('timestamp', 'N/A')}</div>
                    </div>
                    """
                    findings_html.append(finding_html)
                except AttributeError:
                    print(f"[!] Error processing finding: {finding}")
                    continue
                    
        except json.JSONDecodeError:
            # If the file isn't valid JSON, try reading line by line
            print("[!] Could not parse file as single JSON, trying line by line...")
            f.seek(0)  # Reset file pointer to beginning
            for line in f:
                try:
                    finding = json.loads(line)
                    severity = finding.get('info', {}).get('severity', 'info').lower()
                    severity_counts[severity] += 1
                    
                    finding_html = f"""
                    <div class="finding {severity}">
                        <div class="severity-badge" style="background-color: {severity_colors.get(severity, '#2ecc71')}">
                            {severity.upper()}
                        </div>
                        <h3>{html.escape(finding.get('info', {}).get('name', 'Unknown'))}</h3>
                        <p><strong>Host:</strong> {html.escape(finding.get('host', 'N/A'))}</p>
                        <p><strong>Matched At:</strong> {html.escape(finding.get('matched-at', 'N/A'))}</p>
                        <p><strong>Description:</strong> {html.escape(finding.get('info', {}).get('description', 'N/A'))}</p>
                        <div class="timestamp">Discovered: {finding.get('timestamp', 'N/A')}</div>
                    </div>
                    """
                    findings_html.append(finding_html)
                except (json.JSONDecodeError, AttributeError):
                    continue
    
    # Generate severity statistics HTML
    stats_html = []
    for severity, count in severity_counts.items():
        stats_html.append(f"""
        <div class="stat-box" style="border-top: 3px solid {severity_colors[severity]}">
            <h3>{severity.upper()}</h3>
            <p>{count}</p>
        </div>
        """)
    
    # Combine all components
    report_html = html_template.format(
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        target_domain=target_domain,
        severity_stats=''.join(stats_html),
        findings=''.join(findings_html),
        web_services_count=web_services_count,
        web_services_list=web_services_html
    )
    
    # Write the HTML report
    with open(html_file, 'w') as f:
        f.write(report_html)
    
    print(f"[+] HTML report generated: {html_file}")
    return html_file

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 recon.py <domain>")
        sys.exit(1)
    
    domain = sys.argv[1]
    output_dir = setup_output_dir()
    
    # Run the tools in sequence
    subdomains_file = run_subfinder(domain, output_dir)
    live_hosts_file = run_httpx(subdomains_file, output_dir, domain)
    nuclei_json = run_nuclei(live_hosts_file, domain)
    
    if nuclei_json:
        nuclei_csv = convert_nuclei_to_csv(nuclei_json, domain)
        html_report = generate_html_report(nuclei_json, output_dir, live_hosts_file, domain)
        generate_landing_page(output_dir)  # Generate/update the landing page
        print(f"[+] Scan complete! Results saved in {output_dir}/")
    else:
        print("[!] Scan failed during nuclei execution")
        sys.exit(1)

if __name__ == "__main__":
    main() 