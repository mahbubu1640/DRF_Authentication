from django.shortcuts import render
from rest_framework.permissions import IsAuthenticated
# Create your views here.
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import UserRegistrationSerializer, TokenSerializer
from .models import User

class UserRegistrationView(APIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=201)
        return Response(serializer.errors, status=400)



class UserLoginView(APIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        user = User.objects.filter(email=email).first()

        if user and user.check_password(password):
            refresh = RefreshToken.for_user(user)
            token_serializer = TokenSerializer(data={
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            })
            if token_serializer.is_valid():
                return Response(token_serializer.data, status=200)
        
        return Response({'error': 'Invalid email or password'}, status=401)


class UserLogoutView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        refresh_token = request.data.get('refresh_token')
        if refresh_token:
            try:
                token = RefreshToken(refresh_token)
                token.blacklist()
                return Response({'message': 'Successfully logged out.'}, status=200)
            except Exception as e:
                return Response({'error': 'Invalid token or token has already been blacklisted.'}, status=400)
        else:
            return Response({'error': 'No refresh token provided.'}, status=400)
