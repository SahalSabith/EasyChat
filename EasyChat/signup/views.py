from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
from django.shortcuts import get_object_or_404
from django.core.files.base import ContentFile
import base64
import json

from .models import User, OTP
from .serializers import SignupSerializer, VerifyOTPSerializer, LoginSerializer, UserProfileSerializer
from .utils import send_otp_email
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator



class SignupView(APIView):
    def post(self, request):
        serializer = SignupSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            
            user_data = {
                'username': serializer.validated_data['username'],
                'email': email,
                'password': serializer.validated_data['password'],
                'consent_email_updates': serializer.validated_data.get('consent_email_updates', False),
            }
            
            if 'profile_image' in serializer.validated_data and serializer.validated_data['profile_image']:
                user_data['has_profile_image'] = True
            
            if send_otp_email(email, user_data):
                return Response({
                    "message": "Verification code sent. Please verify to complete registration.",
                    "email": email,
                    "signup_details": {
                        "username": user_data['username'],
                        "email": email,
                        "consent_email_updates": user_data['consent_email_updates']
                    }
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    "error": "Failed to send verification email.",
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyOTPView(APIView):
    def post(self, request):
        serializer = VerifyOTPSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp_code = serializer.validated_data['otp']
            
            try:
                otp = OTP.objects.filter(email=email, is_used=False).latest('created_at')
            except OTP.DoesNotExist:
                return Response({"error": "No active OTP found"}, status=status.HTTP_400_BAD_REQUEST)
            
            if not otp.is_valid():
                return Response({"error": "OTP has expired"}, status=status.HTTP_400_BAD_REQUEST)
            
            if otp.otp_code != otp_code:
                return Response({"error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)
            
            otp.is_used = True
            otp.save()
            
            user_data = otp.get_user_data()
            if not user_data:
                return Response({"error": "User data not found"}, status=status.HTTP_400_BAD_REQUEST)
            
            user = User.objects.create_user(
                username=user_data['username'],
                email=user_data['email'],
                password=user_data['password'],
                consent_email_updates=user_data.get('consent_email_updates', False),
                is_active=True,
                is_verified=True
            )
            
            if 'profile_image' in request.data and request.data['profile_image']:
                try:
                    if request.data['profile_image'].startswith('data:image'):
                        format, imgstr = request.data['profile_image'].split(';base64,')
                        ext = format.split('/')[-1]
                        user.profile_image = ContentFile(base64.b64decode(imgstr), name=f'{user.username}_profile.{ext}')
                        user.save()
                except Exception as e:
                    pass
            
            refresh = RefreshToken.for_user(user)
            
            profile_serializer = UserProfileSerializer(user, context={'request': request})
            
            return Response({
                "message": "Account verified and created successfully",
                "refresh": str(refresh),
                "access": str(refresh.access_token),
                "user_profile": profile_serializer.data
            }, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            
            refresh = RefreshToken.for_user(user)
            
            profile_serializer = UserProfileSerializer(user, context={'request': request})
            
            return Response({
                "refresh": str(refresh),
                "access": str(refresh.access_token),
                "user_profile": profile_serializer.data
            }, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"message": "Logged out successfully"}, status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class ResendOTPView(APIView):
    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({"error": "Email is required"}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            latest_otp = OTP.objects.filter(email=email).latest('created_at')
            user_data = latest_otp.get_user_data()
        except OTP.DoesNotExist:
            user_data = None
        
        try:
            user = User.objects.get(email=email)
            if user.is_verified:
                return Response({"error": "User is already verified"}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            pass
        
        if send_otp_email(email, user_data):
            return Response({
                "message": "New verification code sent to your email",
                "email": email,
                "signup_details": {
                    "username": user_data.get('username') if user_data else None,
                    "email": email,
                    "consent_email_updates": user_data.get('consent_email_updates', False) if user_data else False
                }
            }, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Failed to send verification email"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        serializer = UserProfileSerializer(request.user, context={'request': request})
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def put(self, request):
        serializer = UserProfileSerializer(request.user, data=request.data, 
                                         partial=True, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
















    