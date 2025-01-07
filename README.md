# Lyra - Simple Attack Surface Management



Lyra automates the process of subdomain enumeration, web service discovery, and vulnerability scanning using Project Discovery's tools. It generates comprehensive reports in multiple formats (JSON, CSV, and HTML).



## Features



- Subdomain enumeration using subfinder

- Web service discovery using httpx

- Vulnerability scanning using nuclei

- Multiple output formats:

  - JSON output for raw data

  - CSV format for data analysis

  - User-friendly HTML report

- Color-coded severity indicators

- Domain-specific file naming

- Automated output organization



## Prerequisites



- Docker installed on your system

- Basic understanding of command line operations



## Installation



1. Clone this repository:



git clone <repository-url>

cd <repository-name>



2. Build the Docker image:



docker build -t lyra-tools .



## Usage



1. Run the container with volume mounting for persistent output:



docker run -it -v $(pwd)/output:/app/output lyra-tools



2. Inside the container, run the script with a target domain:



python3 recon.py example.com



### Output Files



The script creates the following domain-specific files in the output directory:



- `{domain}_subdomains.txt`: List of discovered subdomains

- `{domain}_live_hosts.txt`: List of active web services

- `{domain}_nuclei_results.json`: Raw nuclei scan results

- `{domain}_nuclei_results.csv`: Formatted scan results

- `{domain}_nuclei_report.html`: User-friendly HTML report

- `styles.css`: Styling for HTML report



### HTML Report Features



The HTML report includes:

- Target domain information

- Scan timestamp

- Summary statistics by severity

- List of discovered web services

- Detailed findings with:

  - Severity badges

  - Finding name

  - Host information

  - Description

  - Discovery timestamp



### CSV Output Format



The CSV file includes the following columns:

- timestamp: Time of discovery

- template-id: Nuclei template identifier

- info.severity: Finding severity level

- host: Target host

- matched-at: Specific URL/endpoint

- info.name: Vulnerability name

- info.description: Detailed description



## Project Structure



.

├── Dockerfile

├── README.md

├── recon.py

└── templates/

    ├── report_template.html

    └── styles.css



## Docker Components



- Alpine Linux base image with Go

- Python 3

- Project Discovery tools:

  - subfinder

  - httpx

  - nuclei



## Script Workflow



1. `setup_output_dir()`: Creates output directory

2. `run_subfinder()`: Enumerates subdomains

3. `run_httpx()`: Identifies active web services

4. `run_nuclei()`: Performs vulnerability scanning

5. `convert_nuclei_to_csv()`: Converts results to CSV

6. `generate_html_report()`: Creates HTML report



## Example Usage



# Build the Docker image

docker build -t lyra-tools .



# Run the container

docker run -it -v $(pwd)/output:/app/output lyra-tools



# Inside the container

python3 recon.py example.com



Example output:



[+] Running subfinder against example.com

[+] Running httpx to identify live web services

[+] Running nuclei scan

[+] Converting nuclei results to CSV

[+] HTML report generated: output/example.com_nuclei_report.html

[+] Scan complete! Results saved in output/



## Notes



- Results are saved in the mounted volume for persistence

- Domain-specific file naming prevents overwriting

- CSV format enables easy data analysis

- HTML report provides user-friendly interface


