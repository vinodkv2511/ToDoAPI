
from django.contrib.auth.models import User
from rest_framework import authentication, exceptions, HTTP_HEADER_ENCODING
import jwt
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned


class ToDoTokenAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):

        # Get the token from request header
        auth = request.META.get('HTTP_AUTHORIZATION', b'')
        if isinstance(auth, str):
            # Work around django test client oddness
            auth = auth.encode(HTTP_HEADER_ENCODING)

        auth = auth.split()

        if not auth or auth[0].lower() != 'bearer'.encode():
            return None

        if len(auth) == 1:
            msg = 'Invalid token header. No credentials provided.'
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = 'Invalid token header. Token string should not contain spaces.'
            raise exceptions.AuthenticationFailed(msg)

        try:
            token = auth[1].decode()
        except UnicodeError:
            msg = 'Invalid token header. Token string should not contain invalid characters.'
            raise exceptions.AuthenticationFailed(msg)

        # Validating the token
        try:
            decoded_token_payload = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
        except jwt.exceptions.InvalidSignatureError:
            raise exceptions.AuthenticationFailed("Invalid Signature, Token tampered!")
        except jwt.exceptions.ExpiredSignatureError:
            raise exceptions.AuthenticationFailed("Token expired")
        except (jwt.exceptions.InvalidTokenError, jwt.exceptions.DecodeError):
            raise exceptions.AuthenticationFailed("Invalid Token")

        # Checking token type
        if not decoded_token_payload['type'] or decoded_token_payload['type'] != 'access':
            return None

        try:
            user = User.objects.get(username=decoded_token_payload['username'])
        except ObjectDoesNotExist:
            raise exceptions.AuthenticationFailed("User doesn't exist")
        except MultipleObjectsReturned:
            raise exceptions.AuthenticationFailed("Multiple users found")

        return user, None


