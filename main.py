#!/usr/bin/env python3

import os
import sys
import json
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Any

def get_input(name: str, default: str = '') -> str:
    """Get input value from environment variables."""
    return os.environ.get(f'INPUT_{name.upper().replace("-", "_")}', default)

def set_output(name: str, value: str) -> None:
    """Set output value for GitHub Actions."""
    output_file = os.environ.get('GITHUB_OUTPUT')
    if output_file:
        with open(output_file, 'a') as f:
            f.write(f'{name}={value}\n')

def run_command(cmd: List[str], cwd: str = None) -> tuple:
    """Run a shell command and return output and exit code."""
    try:
        result = subprocess.run(
            cmd, 
            cwd=cwd, 
            capture_output=True, 
            text=True, 
            check=False
        )
        return result.stdout, result.stderr, result.returncode
    except Exception as e:
        return '', str(e), 1

def parse_safety_output(output: str) -> List[Dict[str, Any]]:
    """Parse safety JSON output into structured vulnerabilities."""
    vulnerabilities = []
    try:
        if output.strip():
            data = json.loads(output)
            for vuln in data:
                vulnerabilities.append({
                    'id': vuln.get('id', 'unknown'),
                    'package': vuln.get('package_name', 'unknown'),
                    'version': vuln.get('analyzed_version', 'unknown'),
                    'vulnerability': vuln.get('vulnerability_id', 'unknown'),
                    'severity': 'high',  # Safety doesn't provide severity
                    'description': vuln.get('advisory', 'No description available')
                })
    except (json.JSONDecodeError, KeyError) as e:
        print(f'Warning: Failed to parse safety output: {e}')
    return vulnerabilities

def parse_pip_audit_output(output: str) -> List[Dict[str, Any]]:
    """Parse pip-audit JSON output into structured vulnerabilities."""
    vulnerabilities = []
    try:
        if output.strip():
            data = json.loads(output)
            for vuln in data:
                vulnerabilities.append({
                    'id': vuln.get('id', 'unknown'),
                    'package': vuln.get('package', 'unknown'),
                    'version': vuln.get('version', 'unknown'),
                    'vulnerability': vuln.get('id', 'unknown'),
                    'severity': 'medium',  # pip-audit doesn't provide severity consistently
                    'description': vuln.get('description', 'No description available')
                })
    except (json.JSONDecodeError, KeyError) as e:
        print(f'Warning: Failed to parse pip-audit output: {e}')
    return vulnerabilities

def filter_vulnerabilities(vulns: List[Dict[str, Any]], ignore_list: List[str]) -> List[Dict[str, Any]]:
    """Filter out ignored vulnerabilities."""
    if not ignore_list:
        return vulns
    
    filtered = []
    for vuln in vulns:
        vuln_id = vuln.get('vulnerability', '')
        if vuln_id not in ignore_list:
            filtered.append(vuln)
        else:
            print(f'Info: Ignoring vulnerability {vuln_id} as requested')
    
    return filtered

def generate_text_report(vulnerabilities: List[Dict[str, Any]]) -> str:
    """Generate a text format security report."""
    if not vulnerabilities:
        return 'No security vulnerabilities found.\n'
    
    report = f'Security Scan Report\n'
    report += f'=====================\n\n'
    report += f'Found {len(vulnerabilities)} vulnerabilities:\n\n'
    
    for i, vuln in enumerate(vulnerabilities, 1):
        report += f'{i}. {vuln["package"]} ({vuln["version"]})\n'
        report += f'   Vulnerability: {vuln["vulnerability"]}\n'
        report += f'   Severity: {vuln["severity"]}\n'
        report += f'   Description: {vuln["description"]}\n\n'
    
    return report

def generate_json_report(vulnerabilities: List[Dict[str, Any]]) -> str:
    """Generate a JSON format security report."""
    return json.dumps({
        'vulnerabilities': vulnerabilities,
        'count': len(vulnerabilities)
    }, indent=2)

def generate_sarif_report(vulnerabilities: List[Dict[str, Any]]) -> str:
    """Generate a SARIF format security report for GitHub Security tab."""
    rules = []
    results = []
    
    for vuln in vulnerabilities:
        rule_id = f'security/{vuln["vulnerability"]}'
        rules.append({
            'id': rule_id,
            'name': f'Security vulnerability in {vuln["package"]}',
            'shortDescription': {'text': vuln['description'][:100]},
            'fullDescription': {'text': vuln['description']},
            'defaultConfiguration': {
                'level': 'error' if vuln['severity'] == 'high' else 'warning'
            }
        })
        
        results.append({
            'ruleId': rule_id,
            'message': {
                'text': f'Security vulnerability found in {vuln["package"]} {vuln["version"]}'
            },
            'locations': [{
                'physicalLocation': {
                    'artifactLocation': {'uri': 'requirements.txt'},
                    'region': {'startLine': 1, 'startColumn': 1}
                }
            }]
        })
    
    sarif = {
        'version': '2.1.0',
        'runs': [{
            'tool': {
                'driver': {
                    'name': 'Python Dependency Scanner',
                    'version': '1.0.0',
                    'rules': rules
                }
            },
            'results': results
        }]
    }
    
    return json.dumps(sarif, indent=2)

def main():
    """Main function to run the dependency scanner."""
    try:
        # Get inputs
        requirements_file = get_input('requirements-file', 'requirements.txt')
        ignore_vulns = get_input('ignore-vulnerabilities', '')
        fail_on_vulns = get_input('fail-on-vulnerabilities', 'true').lower() == 'true'
        output_format = get_input('output-format', 'text')
        working_dir = get_input('working-directory', '.')
        
        # Validate inputs
        if output_format not in ['text', 'json', 'sarif']:
            print(f'Error: Invalid output format "{output_format}". Must be text, json, or sarif.')
            sys.exit(1)
        
        # Change to working directory
        os.chdir(working_dir)
        
        # Check if requirements file exists
        if not os.path.exists(requirements_file):
            print(f'Warning: Requirements file {requirements_file} not found. Creating empty file for scan.')
            Path(requirements_file).touch()
        
        # Parse ignore list
        ignore_list = [v.strip() for v in ignore_vulns.split(',') if v.strip()]
        
        print(f'Scanning dependencies in {requirements_file}...')
        
        all_vulnerabilities = []
        
        # Run safety check
        print('Running safety scan...')
        safety_cmd = ['safety', 'check', '-r', requirements_file, '--json']
        safety_stdout, safety_stderr, safety_code = run_command(safety_cmd)
        
        if safety_code == 0:
            print('Safety scan completed - no vulnerabilities found')
        elif safety_code == 64:  # Safety found vulnerabilities
            print('Safety scan found vulnerabilities')
            safety_vulns = parse_safety_output(safety_stdout)
            all_vulnerabilities.extend(safety_vulns)
        else:
            print(f'Safety scan failed with exit code {safety_code}')
            if safety_stderr:
                print(f'Safety error: {safety_stderr}')
        
        # Run pip-audit check
        print('Running pip-audit scan...')
        audit_cmd = ['pip-audit', '-r', requirements_file, '--format=json']
        audit_stdout, audit_stderr, audit_code = run_command(audit_cmd)
        
        if audit_code == 0:
            print('Pip-audit scan completed - no vulnerabilities found')
        else:
            print('Pip-audit scan found vulnerabilities or encountered errors')
            if audit_stdout:
                audit_vulns = parse_pip_audit_output(audit_stdout)
                all_vulnerabilities.extend(audit_vulns)
        
        # Filter ignored vulnerabilities
        filtered_vulnerabilities = filter_vulnerabilities(all_vulnerabilities, ignore_list)
        
        # Generate report
        if output_format == 'json':
            report_content = generate_json_report(filtered_vulnerabilities)
        elif output_format == 'sarif':
            report_content = generate_sarif_report(filtered_vulnerabilities)
        else:
            report_content = generate_text_report(filtered_vulnerabilities)
        
        # Write report to file
        report_filename = f'security-report.{output_format}'
        with open(report_filename, 'w') as f:
            f.write(report_content)
        
        # Output results
        print(report_content)
        
        # Set GitHub outputs
        set_output('vulnerabilities-found', str(len(filtered_vulnerabilities)))
        set_output('report-file', report_filename)
        
        # Determine exit code
        if filtered_vulnerabilities and fail_on_vulns:
            print(f'Error: Found {len(filtered_vulnerabilities)} vulnerabilities. Failing as requested.')
            set_output('exit-code', '1')
            sys.exit(1)
        else:
            print(f'Success: Scan completed. Found {len(filtered_vulnerabilities)} vulnerabilities.')
            set_output('exit-code', '0')
            sys.exit(0)
    
    except Exception as e:
        print(f'Error: Unexpected error during scan: {e}')
        set_output('vulnerabilities-found', '0')
        set_output('report-file', '')
        set_output('exit-code', '1')
        sys.exit(1)

if __name__ == '__main__':
    main()