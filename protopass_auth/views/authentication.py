import srp
import base64
import binascii
from rest_framework.authtoken.models import Token
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.http import HttpResponse, JsonResponse
from django.utils.crypto import get_random_string
from django.core.mail import send_mail
from django.contrib.auth.models import User
from rest_framework.views import APIView
from rest_framework import permissions
from protopass_auth.models.activation_id import ActivationId
from protopass_auth.models.authprofile import AuthProfile
from protopass_backend_project import settings


class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):

        try:
            email = request.data['email']
            salt = base64.b64decode(request.data['salt'])
            verifier = binascii.unhexlify(request.data['verifier'])

            validate_email(email)
        except KeyError as e:
            return JsonResponse({'error': "{} is missing!".format(e.args[0])}, status=400)
        except ValidationError as e:
            return JsonResponse({'error': e.message}, status=400)
        except binascii.Error:
            return JsonResponse({'error': 'base64/hex format error'}, status=400)

        if len(User.objects.filter(username=email)) > 0:
            return JsonResponse({'error': 'User already exists'}, status=403)

        user = User.objects.create(username=email, email=email, is_active=False)
        AuthProfile.objects.create(user=user, salt=salt, verifier=verifier)

        activation_id = ActivationId.objects.create(user=user, activation_id=get_random_string(length=32))

        send_mail("Protopass activation",
                  "http://" + request.get_host() + "/validate?email=" + email + "&id=" + activation_id.activation_id,
                  settings.EMAIL_HOST_USER,
                  [email],
                  fail_silently=False)

        return HttpResponse()


class ChallengeView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):

        try:
            email = request.data['email']
            challenge = binascii.unhexlify(request.data['challenge'])

            validate_email(email)
            user = User.objects.get(username=email)
        except KeyError as e:
            return JsonResponse({'error': "{} is missing!".format(e.args[0])}, status=400)
        except User.DoesNotExist as e:
            return JsonResponse({'error': "User does not exist!"}, status=403)
        except ValidationError as e:
            return JsonResponse({'error': e.message}, status=400)
        except binascii.Error:
            return JsonResponse({'error': 'hex format error'}, status=400)

        svr = srp.Verifier(email, user.auth_profile.salt, user.auth_profile.verifier, challenge)
        salt, server_challenge = svr.get_challenge()

        user.auth_profile.client_challenge = challenge
        user.auth_profile.server_challenge_id = svr.get_ephemeral_secret()
        user.auth_profile.save()

        return JsonResponse({
            'salt': base64.b64encode(salt).decode('utf-8'),
            'serverChallenge': binascii.hexlify(server_challenge).decode('utf-8')
        })


class AuthenticateView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        try:
            email = request.data['email']
            client_proof = binascii.unhexlify(request.data['clientProof'])

            validate_email(email)
            user = User.objects.get(username=email)
        except KeyError as e:
            return JsonResponse({'error': "{} is missing!".format(e.args[0])}, status=400)
        except User.DoesNotExist as e:
            return JsonResponse({'error': "User does not exist!"}, status=403)
        except ValidationError as e:
            return JsonResponse({'error': e.message}, status=400)
        except binascii.Error:
            return JsonResponse({'error': 'hex format error'}, status=400)

        svr = srp.Verifier(email,
                           user.auth_profile.salt,
                           user.auth_profile.verifier,
                           user.auth_profile.client_challenge,
                           bytes_b=user.auth_profile.server_challenge_id)

        HAMK = svr.verify_session(client_proof)

        if HAMK is None:
            return JsonResponse({'error': "Login failed!"}, status=403)
        else:
            token = Token.objects.get_or_create(user=user)[0]

            result = {}
            result['salt'] = base64.b64encode(user.auth_profile.salt).decode('utf-8')
            result['serverProof'] = binascii.hexlify(HAMK).decode('utf-8')
            result['sessionId'] = str(token)
            return JsonResponse(result)


class LogoutView(APIView):

    def get(self, request):
        if request.user.is_anonymous:
            return JsonResponse({"error": "authentication failed"}, status=403)
        request.user.auth_token.delete()
        return HttpResponse()
