from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated


class AuthenticatedView(APIView):
    permission_classes = [IsAuthenticated, ]

    def get(self, request):
        msg = {'message': f'Hi {request.user.username}! Congratulations on being authenticated!'}
        return Response(msg, status=status.HTTP_200_OK)
