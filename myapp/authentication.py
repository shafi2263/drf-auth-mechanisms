import base64

from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model

from rest_framework import exceptions
from rest_framework.authentication import BaseAuthentication


def get_authorization_header(request):
    auth = request.META.get("HTTP_AUTHORIZATION", "")
    return auth


class BasicAuthentication(BaseAuthentication):
    www_authenticate_realm = "api"

    def authenticate_header(self, request):
        print("We have come here")
        return f"Basic realm={self.www_authenticate_realm}"

    def authenticate(self, request):
        auth = get_authorization_header(request).split()

        if not auth or auth[0].lower() != "basic":
            return None

        if len(auth) == 1:
            raise exceptions.AuthenticationFailed("Invalid basic header. No credentials provided.")
        if len(auth) > 2:
            raise exceptions.AuthenticationFailed("Invalid basic header. Credential string is not properly formatted")

        try:
            auth_decoded = base64.b64decode(auth[1]).decode("utf-8")
            username, password = auth_decoded.split(":")
        except (UnicodeDecodeError, ValueError):
            raise exceptions.AuthenticationFailed("Invalid basic header. Credentials not correctly encoded")

        return self.authenticate_credentials(username, password, request)

    def authenticate_credentials(self, username, password, request=None):
        credentials = {
            get_user_model().USERNAME_FIELD: username,
            "password": password
        }

        user = authenticate(request=request, **credentials)

        if user is None:
            raise exceptions.AuthenticationFailed("Invalid username or password")

        if not user.is_active:
            raise exceptions.AuthenticationFailed("User is inactive")

        return user, None
