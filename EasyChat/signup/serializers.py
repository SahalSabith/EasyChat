from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from .models import User, OTP
import base64
from django.core.files.base import ContentFile


class ProfileImageField(serializers.ImageField):
    def to_internal_value(self, data):
        if isinstance(data, str) and data.startswith('data:image'):
            format, imgstr = data.split(';base64,') 
            ext = format.split('/')[-1]
            
            data = ContentFile(base64.b64decode(imgstr), name=f'profile.{ext}')
        
        return super().to_internal_value(data)


class SignupSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    email = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)
    consent_email_updates = serializers.BooleanField(required=False, default=False)
    profile_image = ProfileImageField(required=False, allow_null=True)

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        
        if User.objects.filter(email=attrs['email']).exists():
            raise serializers.ValidationError({"email": "Email already registered."})
        
        if User.objects.filter(username=attrs['username']).exists():
            raise serializers.ValidationError({"username": "Username already taken."})
            
        return attrs


class VerifyOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6, min_length=6)


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(required=False)
    email = serializers.EmailField(required=False)
    password = serializers.CharField()

    def validate(self, attrs):
        username = attrs.get('username')
        email = attrs.get('email')
        password = attrs.get('password')

        if not username and not email:
            raise serializers.ValidationError({"error": "Must include either username or email"})

        if email:
            try:
                user = User.objects.get(email=email)
                username = user.username
            except User.DoesNotExist:
                raise serializers.ValidationError({"email": "No user found with this email address"})

        user = authenticate(username=username, password=password)
        
        if not user:
            raise serializers.ValidationError({"error": "Invalid credentials"})
        
        if not user.is_verified:
            raise serializers.ValidationError({"error": "Account is not verified"})

        attrs['user'] = user
        return attrs


class UserProfileSerializer(serializers.ModelSerializer):
    profile_image = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'profile_image', 'consent_email_updates', 
                  'is_verified', 'date_joined', 'created_at', 'updated_at')
        read_only_fields = ('id', 'email', 'is_verified', 'date_joined', 'created_at', 'updated_at')
    
    def get_profile_image(self, obj):
        if obj.profile_image:
            return self.context['request'].build_absolute_uri(obj.profile_image.url)
        return None