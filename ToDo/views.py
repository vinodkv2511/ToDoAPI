# Views.py
# author - Vinod Krishna Vellampalli

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from django.core.exceptions import ValidationError
from django.core.validators import validate_email


class HelloWorld(APIView):
    def get(self, request):
        return Response('HELLO WORLD! from Django.')


# View class to Register users
class Register(APIView):
    def post(self, request):
        # This order of required params is important as they are used to set variables by index
        required_params = ['username', 'password', 'email']
        try:
            data = request.data
            if all(key in data for key in required_params):
                try:
                    if self.validate_input(required_params[0], data[required_params[0]]):
                        user_name = data[required_params[0]]
                    else:
                        raise ValidationError('Invalid username, it can\'t be empty')

                    if self.validate_input(required_params[1], data[required_params[1]]):
                        password = data[required_params[1]]
                    else:
                        raise ValidationError('Invalid Password, password should be at least 8 characters long')

                    if self.validate_input(required_params[2], data[required_params[2]]):
                        email = data[required_params[2]]
                    else:
                        raise ValidationError('Invalid Email')

                except ValidationError as er:
                    return Response({"error": str(er.messages[0])}, status=status.HTTP_400_BAD_REQUEST)

                # Now it is considered that the input is valid
                # We need to make sure that the username doesn't exist already
                if User.objects.filter(username=user_name).exists():
                    return Response({"error": "Username already taken, please try with a different username"}, status=status.HTTP_400_BAD_REQUEST)
                if User.objects.filter(email=email).exists():
                    return Response({"error": "E-mail already in use, please try logging in instead"}, status=status.HTTP_400_BAD_REQUEST)

                new_user = User()
                new_user.username = user_name
                new_user.password = make_password(password)
                new_user.email = email
                try:
                    new_user.first_name = data['firstname'] if data['firstname'] is not None else ""
                except KeyError as err:
                    print("Error while parsing firstname : "+str(err))
                try:
                    new_user.last_name = data['lastname'] if data['lastname'] is not None else ""
                except KeyError as err:
                    print("Error while parsing lastname : " + str(err))

                new_user.save()

                return Response({"status": "Success"}, status=status.HTTP_201_CREATED)

            else:
                return Response({"error": "Required param(s) missing, Please include and retry again"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as exp:
            print("Unexpected exception occurred: "+str(exp))
            return Response({"error": "Unexpected error occurred, please report this to Admin"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def validate_input(self, param, value):
        if param == 'username':
            if value is not None and type(value) == str and len(value) > 0:
                return True
            else:
                return False
        elif param == 'password':
            if value is not None and type(value) == str and len(value) >= 8:
                return True
            else:
                return False
        elif param == 'email':
            if value is not None and type(value) == str and len(value) > 0:
                try:
                    validate_email(value)
                except ValidationError:
                    return False
                else:
                    return True
            else:
                return False
        else:
            return False



