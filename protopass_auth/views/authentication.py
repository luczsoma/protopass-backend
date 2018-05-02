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
from urllib.parse import urlencode


class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):

        try:
            email = request.data['email']
            salt = base64.b64decode(request.data['salt'])
            verifier = binascii.unhexlify(request.data['verifier'])

            validate_email(email)
        except KeyError:
            return JsonResponse({'error': "BadInput"}, status=400)
        except ValidationError:
            return JsonResponse({'error': "BadInput"}, status=400)
        except binascii.Error:
            return JsonResponse({'error': 'SaltNotValid'}, status=400)

        if len(User.objects.filter(username=email)) > 0:
            return JsonResponse({'error': 'UserAlreadyExists'}, status=403)

        user = User.objects.create(username=email, email=email, is_active=False)
        AuthProfile.objects.create(user=user, salt=salt, verifier=verifier)

        activation_id = ActivationId.objects.create(user=user, activation_id=get_random_string(length=32))

        send_mail("Protopass activation",
                  "https://protopass-frontend.azurewebsites.net/validate?" + urlencode({'email': email, 'id': activation_id.activation_id}),
                  settings.EMAIL_HOST_USER,
                  [email],
                  fail_silently=False)

        return HttpResponse()


class ChallengeView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):

        try:
            email = request.data['email']
            challenge = binascii.unhexlify(request.data['clientChallenge'])

            validate_email(email)
            user = User.objects.get(username=email)
        except KeyError:
            return JsonResponse({'error': "BadInput"}, status=400)
        except User.DoesNotExist:
            return JsonResponse({'error': "UserNotExists"}, status=403)
        except ValidationError:
            return JsonResponse({'error': 'EmailNotValid'}, status=400)
        except binascii.Error:
            return JsonResponse({'error': 'BadInput'}, status=400)

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
        except KeyError:
            return JsonResponse({'error': "BadInput"}, status=400)
        except User.DoesNotExist:
            return JsonResponse({'error': "UserNotExists"}, status=403)
        except ValidationError:
            return JsonResponse({'error': 'EmailNotValid'}, status=400)
        except binascii.Error:
            return JsonResponse({'error': 'ClientProofNotValid'}, status=400)

        svr = srp.Verifier(email,
                           user.auth_profile.salt,
                           user.auth_profile.verifier,
                           user.auth_profile.client_challenge,
                           bytes_b=user.auth_profile.server_challenge_id)

        HAMK = svr.verify_session(client_proof)

        if HAMK is None:
            return JsonResponse({'error': "ClientProofIncorrect"}, status=403)
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
            return JsonResponse({"error": "InvalidSession"}, status=403)
        request.user.auth_token.delete()
        return HttpResponse()


class ChangePasswordView(APIView):

    def post(self, request):
        try:
            email = request.data['email']
            salt = base64.b64decode(request.data['salt'])
            verifier = binascii.unhexlify(request.data['verifier'])

            validate_email(email)
        except KeyError:
            return JsonResponse({'error': "BadInput"}, status=400)
        except ValidationError:
            return JsonResponse({'error': "EmailNotValid"}, status=400)
        except binascii.Error:
            return JsonResponse({'error': 'SaltNotValid'}, status=400)

        request.user.username = email
        request.user.email = email
        request.user.auth_profile.salt = salt
        request.user.auth_profile.verifier = verifier
        request.user.auth_profile.save()
        request.user.save()

        return HttpResponse()


class ResetPasswordView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        email = request.query_params.get('email')

        if email is None:
            return JsonResponse({'error': 'BadInput'}, status=400)

        try:
            validate_email(email)
            user = User.objects.get(username=email)
        except User.DoesNotExist:
            return JsonResponse({'error': 'UserNotExists'}, status=403)
        except ValidationError:
            return JsonResponse({'error': 'EmailNotValid'}, status=400)

        reset_id = get_random_string(length=32)
        user.auth_profile.password_reset_id = reset_id
        user.auth_profile.save()

        send_mail("Protopass password reset",
                  "https://protopass-frontend.azurewebsites.net/resetPassword?" + urlencode({'id': reset_id}),
                  settings.EMAIL_HOST_USER,
                  [email],
                  fail_silently=False)

        return HttpResponse()

    def post(self, request):

        reset_id = request.query_params.get('id')

        if reset_id is None:
            return JsonResponse({'error': 'BadInput'}, status=400)

        try:
            salt = base64.b64decode(request.data['salt'])
            verifier = binascii.unhexlify(request.data['verifier'])
        except KeyError:
            return JsonResponse({'error': "BadInput"}, status=400)
        except binascii.Error:
            return JsonResponse({'error': 'SaltNotValid'}, status=400)

        profiles = AuthProfile.objects.filter(password_reset_id=reset_id)
        if len(profiles > 0):
            profile = profiles[0]
        else:
            return JsonResponse({'error': 'InvalidId'}, status=403)

        profile.salt = salt
        profile.verifier = verifier
        profile.save()

        return HttpResponse()
