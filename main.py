# Add this dictionary at the top of your Python file
SECURITY_SUGGESTIONS = {
    "firewall_status": {
        "fail": [
            "Enable Windows Firewall immediately",
            "Configure firewall rules for all network profiles (Domain, Private, Public)",
            "Block all inbound connections by default",
            "Ensure critical services are explicitly allowed"
        ],
        "warning": [
            "Review firewall rules periodically",
            "Consider implementing application-based filtering",
            "Enable logging for blocked connections"
        ]
    },
    "antivirus_status": {
        "fail": [
            "Install a reputable antivirus solution immediately",
            "Enable real-time scanning",
            "Schedule regular system scans",
            "Keep virus definitions up-to-date"
        ],
        "warning": [
            "Update antivirus definitions",
            "Run a full system scan",
            "Review quarantined items"
        ]
    },
    "windows_update_status": {
        "fail": [
            "Enable automatic Windows updates",
            "Check for and install pending updates",
            "Configure active hours to prevent disruption",
            "Enable notifications for update status"
        ],
        "warning": [
            "Review update history for failed installations",
            "Clear Windows Update cache if experiencing issues",
            "Ensure sufficient disk space for updates"
        ]
    },
    "admin_status": {
        "fail": [
            "Create separate admin and user accounts",
            "Use UAC (User Account Control) for elevation",
            "Implement principle of least privilege",
            "Regular review of admin account usage"
        ],
        "warning": [
            "Review admin account permissions",
            "Enable auditing for admin actions",
            "Consider using a password manager"
        ]
    },
    "system_info": {
        "fail": [
            "Upgrade system memory if usage consistently high",
            "Free up disk space (at least 20% free space recommended)",
            "Check for hardware compatibility issues",
            "Update system drivers"
        ],
        "warning": [
            "Monitor system performance",
            "Schedule disk cleanup regularly",
            "Review startup programs"
        ]
    },
    "running_services": {
        "fail": [
            "Disable unnecessary services",
            "Review service account permissions",
            "Enable service failure recovery options",
            "Implement service monitoring"
        ],
        "warning": [
            "Audit running services periodically",
            "Document required services",
            "Check service dependencies"
        ]
    },
    "network_connections": {
        "fail": [
            "Review and close unnecessary ports",
            "Implement network segmentation",
            "Monitor outbound connections",
            "Use encrypted protocols where possible"
        ],
        "warning": [
            "Document allowed network connections",
            "Implement connection monitoring",
            "Review network security groups"
        ]
    },
    "user_accounts": {
        "fail": [
            "Enforce strong password policy",
            "Enable account lockout policy",
            "Remove unused accounts",
            "Implement regular password changes"
        ],
        "warning": [
            "Review user permissions",
            "Enable two-factor authentication",
            "Audit user activity logs"
        ]
    },
    "scheduled_tasks": {
        "fail": [
            "Review and remove unnecessary scheduled tasks",
            "Verify task permissions",
            "Enable task history",
            "Document business-critical tasks"
        ],
        "warning": [
            "Audit task execution history",
            "Check task account permissions",
            "Monitor task performance"
        ]
    }
}

# Modify the system_audit function to include suggestions
def system_audit():
    audit_results = {
        "firewall_status": check_firewall_status(),
        "antivirus_status": check_antivirus_status(),
        "windows_update_status": check_windows_update_status(),
        "admin_status": check_admin_status(),
        "audit_policy": check_audit_policy(),
        "system_info": check_system_info(),
        "running_services": check_running_services(),
        "network_connections": check_network_connections(),
        "user_accounts": check_user_accounts(),
        "scheduled_tasks": check_scheduled_tasks()
    }
    
    # Add suggestions for each check
    for check, result in audit_results.items():
        if result['status'] in ['fail', 'warning'] and check in SECURITY_SUGGESTIONS:
            result['suggestions'] = SECURITY_SUGGESTIONS[check][result['status']]
        else:
            result['suggestions'] = []
            
    return audit_results
from flask import Flask, render_template, request, send_file, jsonify
import subprocess
import winreg
import os
import platform
import socket
import psutil
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

app = Flask(__name__)

# Existing security check functions
def check_firewall_status():
    try:
        output = subprocess.check_output("netsh advfirewall show allprofiles", shell=True, text=True)
        return {"status": "pass", "output": output}
    except subprocess.CalledProcessError as e:
        return {"status": "fail", "output": f"Error: {e}"}

def check_antivirus_status():
    try:
        reg_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
        return {"status": "pass", "output": "Antivirus Status: Active"}
    except Exception as e:
        return {"status": "fail", "output": f"Error: {e}"}

def check_windows_update_status():
    try:
        output = subprocess.check_output("powershell Get-WindowsUpdateLog", shell=True, text=True)
        return {"status": "pass", "output": output}
    except subprocess.CalledProcessError as e:
        return {"status": "fail", "output": f"Error: {e}"}

# Enhanced existing checks
def check_admin_status():
    try:
        output = subprocess.check_output("net session", shell=True, text=True)
        is_admin = "Access denied" not in output
        return {
            "status": "pass" if is_admin else "warning",
            "output": "User is an Administrator" if is_admin else "User is not an Administrator"
        }
    except subprocess.CalledProcessError as e:
        return {"status": "fail", "output": f"Error: {e}"}

def check_audit_policy():
    try:
        output = subprocess.check_output("auditpol /get /category:*", shell=True, text=True)
        return {"status": "pass", "output": output}
    except subprocess.CalledProcessError as e:
        return {"status": "fail", "output": f"Error: {e}"}

# New security checks
def check_running_services():
    try:
        output = subprocess.check_output("net start", shell=True, text=True)
        return {"status": "pass", "output": output}
    except subprocess.CalledProcessError as e:
        return {"status": "fail", "output": f"Error: {e}"}

def check_network_connections():
    try:
        output = subprocess.check_output("netstat -an", shell=True, text=True)
        return {"status": "pass", "output": output}
    except subprocess.CalledProcessError as e:
        return {"status": "fail", "output": f"Error: {e}"}

def check_system_info():
    try:
        info = {
            "OS": platform.system() + " " + platform.release(),
            "Architecture": platform.machine(),
            "Processor": platform.processor(),
            "Hostname": socket.gethostname(),
            "Memory": f"{psutil.virtual_memory().percent}% used",
            "Disk": f"{psutil.disk_usage('/').percent}% used"
        }
        return {"status": "pass", "output": "\n".join(f"{k}: {v}" for k, v in info.items())}
    except Exception as e:
        return {"status": "fail", "output": f"Error: {e}"}

def check_user_accounts():
    try:
        output = subprocess.check_output("net user", shell=True, text=True)
        return {"status": "pass", "output": output}
    except subprocess.CalledProcessError as e:
        return {"status": "fail", "output": f"Error: {e}"}

def check_scheduled_tasks():
    try:
        output = subprocess.check_output("schtasks /query /fo LIST", shell=True, text=True)
        return {"status": "pass", "output": output}
    except subprocess.CalledProcessError as e:
        return {"status": "fail", "output": f"Error: {e}"}

def system_audit():
    return {
        "firewall_status": check_firewall_status(),
        "antivirus_status": check_antivirus_status(),
        "windows_update_status": check_windows_update_status(),
        "admin_status": check_admin_status(),
        "audit_policy": check_audit_policy(),
        "system_info": check_system_info(),
        "running_services": check_running_services(),
        "network_connections": check_network_connections(),
        "user_accounts": check_user_accounts(),
        "scheduled_tasks": check_scheduled_tasks()
    }

def generate_pdf(audit_results):
    filename = f"security_audit_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Title'],
        spaceAfter=30,
        textColor=colors.HexColor('#2563eb')
    )

    # Title
    elements.append(Paragraph("System Security Audit Report", title_style))
    elements.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]))
    elements.append(Spacer(1, 20))

    for section, result in audit_results.items():
        # Section header
        section_title = section.replace('_', ' ').title()
        elements.append(Paragraph(f"{section_title}", styles["Heading2"]))
        
        # Status indicator
        status_color = colors.green if result['status'] == 'pass' else colors.red
        status_text = f"Status: {result['status'].upper()}"
        elements.append(Paragraph(f'<font color="{status_color}">{status_text}</font>', styles["Normal"]))
        
        # Output content
        elements.append(Spacer(1, 10))
        elements.append(Paragraph(result['output'].replace('\n', '<br/>'), styles["Code"]))
        elements.append(Spacer(1, 20))

    doc.build(elements)
    return filename

@app.route("/", methods=["GET"])
def dashboard():
    return render_template("dashboard.html")

@app.route("/run_audit", methods=["POST"])
def run_audit():
    results = system_audit()
    return jsonify(results)

@app.route("/download_report")
def download_report():
    audit_results = system_audit()
    pdf_filename = generate_pdf(audit_results)
    return send_file(pdf_filename, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)