# File: emailer.py

import smtplib
from email.message import EmailMessage
from fastapi import HTTPException

def send_verification_email(to_email: str, username: str, token: str):
    verification_link = f"http://127.0.0.1:8000/verify-email?token={token}"
    subject = "Verify your email"

    # HTML version with clickable link
    html_body = f"""\
    <html>
      <body>
        <p>Hello {username},</p>
        <p>Please click the link below to verify your email address:</p>
        <p><a href="{verification_link}">Verify Email</a></p>
        <p>If you did not create this account, please ignore this email.</p>
      </body>
    </html>
    """

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = "<rahulsohaliya.software@gmail.com>"
    msg["To"] = to_email
    msg.set_content("Please view this email in HTML format.")
    msg.add_alternative(html_body, subtype="html")

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as smtp:
            smtp.set_debuglevel(1)
            smtp.starttls()
            smtp.login("rahulsohaliya.software@gmail.com", "rdfxeypwfnqvyist")
            smtp.send_message(msg)
            print("✅ Email sent successfully.")
    except Exception as e:
        print(f"Email send failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to send verification email")
