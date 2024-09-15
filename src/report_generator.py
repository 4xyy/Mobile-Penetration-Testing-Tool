# report_generator.py
def generate_report(vulnerabilities):
    with open('report.txt', 'w') as report_file:
        for vuln in vulnerabilities:
            report_file.write(f"{vuln}\n")
    print("Report generated: report.txt")

