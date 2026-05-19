
import os
import requests

RESEND_API_KEY = os.getenv("RESEND_API_KEY")

def send_otp(email, otp):
    url = "https://api.resend.com/emails"
    headers = {
        "Authorization": f"Bearer {RESEND_API_KEY}",
        "Content-Type": "application/json",
    }
    data = {
        "from": "XBank <onboarding@resend.dev>",
        "to": [email],
        "subject": "XBank OTP Verification",
        "html": f"<h2>Your OTP is {otp}</h2>"
    }
    requests.post(url, headers=headers, json=data)
