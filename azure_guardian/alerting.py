import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

load_dotenv()


def format_findings_as_text(findings, title):
    if not findings:
        return f"{title}\n\nNo issues found. Everything looks clean."

    lines = [f"{title}\n", f"Found {len(findings)} issue(s):\n"]
    for f in findings:
        if "service" in f:  # NSG finding
            lines.append(
                f"[{f['severity']}] NSG '{f['nsg_name']}' (RG: {f['resource_group']}) "
                f"allows {f['service']} (port {f['port']}) from '{f['source']}'"
            )
        else:  # Cost finding
            lines.append(
                f"[{f['severity']}] {f['resource_type']} '{f['resource_name']}' "
                f"(RG: {f['resource_group']}) — {f['issue']}"
            )
    return "\n".join(lines)


def send_email_alert(findings, title="Azure Guardian Report"):
    """
    Sends an email with the scan findings.
    Requires SMTP settings in .env:
    SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, ALERT_EMAIL_TO
    """
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    recipient = os.getenv("ALERT_EMAIL_TO")

    if not all([smtp_host, smtp_user, smtp_password, recipient]):
        print("⚠️  Email alerting not configured — skipping (missing SMTP settings in .env).")
        return False

    body = format_findings_as_text(findings, title)

    msg = MIMEMultipart()
    msg["From"] = smtp_user
    msg["To"] = recipient
    msg["Subject"] = title
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.send_message(msg)
        print(f"✅ Alert email sent to {recipient}")
        return True
    except Exception as e:
        print(f"❌ Failed to send email alert: {e}")
        return False