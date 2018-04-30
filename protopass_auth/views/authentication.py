import srp
import base64
import binascii
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.http import HttpResponse, JsonResponse
from django.utils.crypto import get_random_string
from rest_framework.views import APIView
from django.core.mail import send_mail
from protopass_auth.models.activation_id import ActivationId
from protopass_auth.validators import validate_salt, validate_verifier
from django.contrib.auth.models import User
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
        Profile.objects.create(user=user, salt=base64.b64decode(salt), verifier=binascii.unhexlify(verifier))

        activation_id = ActivationId.objects.create(user=user, activation_id=get_random_string(length=32))

        send_mail("Protopass activation",
                  "http://" + request.get_host() + "/validate?email=" + email + "&id=" + activation_id.activation_id,
                  settings.EMAIL_HOST_USER,
                  [email],
                  fail_silently=False)

        return HttpResponse()


class ChallengeView(APIView):
    def post(self, request):

        try:
            email = request.data['email']
            challenge = request.data['challenge']

            user = User.objects.get(username=email)
        except KeyError as e:
            return JsonResponse({'error': "{} is missing!".format(e.args[0])}, status=400)
        except User.DoesNotExist as e:
            return JsonResponse({'error': "User does not exist!"}, status=400)

        svr = srp.Verifier(email, user.profile.salt, user.profile.verifier, binascii.unhexlify(challenge))
        salt, server_challenge = svr.get_challenge()

        user.profile.client_challenge = binascii.unhexlify(challenge)
        user.profile.server_challenge_id = svr.get_ephemeral_secret()
        user.profile.save()

        return JsonResponse({
            'salt': base64.b64encode(salt).decode('utf-8'),
            'serverChallenge': binascii.hexlify(server_challenge).decode('utf-8')
        })


class AuthenticateView(APIView):
    def post(self, request):
        try:
            email = request.data['email']
            clientProof = request.data['clientProof']

            user = User.objects.get(username=email)
        except KeyError as e:
            return JsonResponse({'error': "{} is missing!".format(e.args[0])}, status=400)
        except User.DoesNotExist as e:
            return JsonResponse({'error': "User does not exist!"}, status=400)

        svr = srp.Verifier(email,
                           user.profile.salt,
                           user.profile.verifier,
                           user.profile.client_challenge,
                           bytes_b=user.profile.server_challenge_id)

        HAMK = svr.verify_session(binascii.unhexlify(clientProof))

        if HAMK is None:
            return HttpResponse("FAIL", status=400)
        else:
            return HttpResponse()


class LogoutView(APIView):
    pass
