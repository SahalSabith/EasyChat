from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
import random
import string
import json

class User(AbstractUser):
    email = models.EmailField(unique=True)
    is_verified = models.BooleanField(default=False)
    consent_email_updates = models.BooleanField(default=False)
    profile_image = models.ImageField(upload_to='profile_images/', null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.username


class OTP(models.Model):
    email = models.EmailField()
    otp_code = models.CharField(max_length=6)
    user_data = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.email} - {self.otp_code}"

    def save(self, *args, **kwargs):
        if not self.otp_code:
            self.otp_code = ''.join(random.choices(string.digits, k=6))
        
        if not self.expires_at:
            self.expires_at = timezone.now() + timezone.timedelta(minutes=2)
        
        super().save(*args, **kwargs)

    def is_valid(self):
        now = timezone.now()
        return not self.is_used and now <= self.expires_at
    
    def get_user_data(self):
        if self.user_data:
            return json.loads(self.user_data)
        return {}
    
    def set_user_data(self, data):
        self.user_data = json.dumps(data)