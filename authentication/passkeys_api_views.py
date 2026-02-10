from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from django.conf import settings
from passkeys.backend import PasskeyModelBackend
from authentication.libs.utils import generate_otp
from django.contrib.auth import login as django_login
from django.http import HttpRequest, JsonResponse
import json

from passkeys.FIDO2 import (
    reg_begin, reg_complete, auth_begin, auth_complete
)
from authentication.models import User
from authentication.serializers import MyTokenObtainPairSerializer
from authentication.signals import user_logged_in
from rest_framework.authentication import SessionAuthentication
from rest_framework_simplejwt.authentication import JWTAuthentication

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

class PasskeyRegisterBeginView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication, SessionAuthentication]

    @swagger_auto_schema(
        operation_description="Initiate Passkey registration for the authenticated user.",
        responses={
            200: openapi.Response(
                description="PublicKey Credential Creation Options",
                examples={
                    "application/json": {
                        "publicKey": {
                            "rp": {"name": "Arna SSO", "id": "localhost"},
                            "user": {"name": "user@example.com", "displayName": "User Name", "id": "base64..."},
                            "challenge": "base64...",
                            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                            "timeout": 60000,
                            "attestation": "direct"
                        }
                    }
                }
            )
        }
    )
    def get(self, request):
        """
        Initiate Passkey registration for the authenticated user.
        Returns the PublicKeyCredentialCreationOptions.
        """
        res = reg_begin(request)
        if hasattr(res, 'content'):
             return Response(json.loads(res.content), status=status.HTTP_200_OK)
        return Response(res, status=status.HTTP_200_OK)


class PasskeyRegisterCompleteView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication, SessionAuthentication]

    @swagger_auto_schema(
        operation_description="Complete Passkey registration.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            description="WebAuthn Registration Response from navigator.credentials.create()",
            example={
                "id": "base64...",
                "rawId": "base64...",
                "response": {
                    "attestationObject": "base64...",
                    "clientDataJSON": "base64..."
                },
                "type": "public-key"
            }
        ),
        responses={
            200: openapi.Response(description="Registration Successful"),
            400: "Registration Failed"
        }
    )
    def post(self, request):
        """
        Complete Passkey registration.
        Expects the WebAuthn response from the frontend as request body.
        """
        res = reg_complete(request)
        
        if hasattr(res, 'content'):
            content = json.loads(res.content)
            if content.get('status') == 'OK':
                 return Response(content, status=status.HTTP_200_OK)
            return Response(content, status=status.HTTP_400_BAD_REQUEST)
            
        return Response({"error": "Registration failed"}, status=status.HTTP_400_BAD_REQUEST)


class PasskeyLoginBeginView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = [SessionAuthentication]

    @swagger_auto_schema(
        operation_description="Initiate Passkey Login.",
        responses={
            200: openapi.Response(
                description="PublicKey Credential Request Options",
                examples={
                    "application/json": {
                        "publicKey": {
                            "challenge": "base64...",
                            "timeout": 60000,
                            "rpId": "localhost",
                            "allowCredentials": []
                        }
                    }
                }
            )
        }
    )
    def get(self, request):
        """
        Initiate Passkey Login.
        Returns PublicKeyCredentialRequestOptions.
        """
        res = auth_begin(request)
        if hasattr(res, 'content'):
             return Response(json.loads(res.content), status=status.HTTP_200_OK)
        return Response(res, status=status.HTTP_200_OK)


class PasskeyLoginCompleteView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = [SessionAuthentication]

    @swagger_auto_schema(
        operation_description="Complete Passkey Login and return JWT tokens.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            description="WebAuthn Assertion Response from navigator.credentials.get()",
            example={
                "id": "base64...",
                "rawId": "base64...",
                "response": {
                    "authenticatorData": "base64...",
                    "clientDataJSON": "base64...",
                    "signature": "base64...",
                    "userHandle": "base64..."
                },
                "type": "public-key"
            }
        ),
        responses={
            200: openapi.Response(
                description="Login Successful, JWT Tokens Returned",
                examples={
                    "application/json": {
                        "refresh": "eyJ...",
                        "access": "eyJ...",
                        "email": "user@example.com",
                        "full_name": "User Name"
                    }
                }
            ),
            400: "Login Failed"
        }
    )
    def post(self, request):
        """
        Complete Passkey Login.
        If successful, issues JWT tokens directly (Skipping MFA).
        """
        res = auth_complete(request)
        
        if hasattr(res, 'content'):
            content = json.loads(res.content)
            
            if content.get('status') == 'OK':
                user = request.user
                
                if user.is_authenticated:
                    refresh = MyTokenObtainPairSerializer.get_token(user)
                    
                    user_logged_in.send(
                        sender=self.__class__, user=user, metadata={"method": "passkey"}
                    )
                    
                    return Response({
                        "refresh": str(refresh),
                        "access": str(refresh.access_token),
                        "email": user.email,
                        "full_name": getattr(user, 'profile', None) and user.profile.full_name or ""
                    }, status=status.HTTP_200_OK)
                else: 
                     return Response({"error": "Authentication succeeded but session invalid."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            return Response(content, status=status.HTTP_400_BAD_REQUEST)
        
        return Response({"error": "Login failed"}, status=status.HTTP_400_BAD_REQUEST)
