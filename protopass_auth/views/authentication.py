from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.http import HttpResponse, JsonResponse
from django.utils.crypto import get_random_string
from rest_framework.views import APIView
from django.contrib.auth.models import User
from django.core.mail import send_mail
from protopass_auth.models.activation_id import ActivationId
from protopass_auth.validators import validate_salt, validate_verifier
from protopass_auth.models.profile import Profile
from protopass_backend_project import settings


class RegisterView(APIView):

    def post(self, request):

        try:
            email = request.data['email']
            salt = request.data['salt']
            verifier = request.data['verifier']

            validate_email(email)
            validate_salt(salt)
            validate_verifier(verifier)
        except KeyError as e:
            return JsonResponse({'error': "{} is missing!".format(e.args[0])}, status=400)
        except ValidationError as e:
            return JsonResponse({'error': e.message}, status=400)

        if len(User.objects.filter(username=email)) > 0:
            return JsonResponse({'error': 'User already exists'}, status=403)

        user = User.objects.create(username=email, email=email, is_active=False)
        Profile.objects.create(user=user, salt=salt, verifier=verifier)

        activation_id = ActivationId.objects.create(user=user, activation_id=get_random_string(length=32))

        send_mail("Protopass activation",
                  "http://" + request.get_host() + "/validate?email=" + email + "&id=" + activation_id.activation_id,
                  settings.EMAIL_HOST_USER,
                  [email],
                  fail_silently=False)

        return HttpResponse()


class LoginView(APIView):
    pass


class LogoutView(APIView):
    pass
