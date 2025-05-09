from django.core.mail import send_mail
from django.conf import settings
from .models import OTP
import logging
import smtplib
import ssl
import certifi
import json

logger = logging.getLogger(__name__)

def send_otp_email(email, user_data=None):
    OTP.objects.filter(email=email, is_used=False).update(is_used=True)
    
    otp = OTP.objects.create(email=email)
    
    if user_data:
        otp.set_user_data(user_data)
        otp.save()
    
    subject = 'Verify your account'
    message = f'Your verification code is: {otp.otp_code}\nThis code will expire in 2 minutes.'
    
    try:
        context = ssl.create_default_context(cafile=certifi.where())
        
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
            server.login(settings.EMAIL_HOST_USER, settings.EMAIL_HOST_PASSWORD)
            server.sendmail(
                settings.EMAIL_HOST_USER, 
                email,                    
                f"Subject: {subject}\n\n{message}"
            )
        return True
    except Exception as e:
        logger.error(f"Failed to send email to {email}: {str(e)}")
        return False