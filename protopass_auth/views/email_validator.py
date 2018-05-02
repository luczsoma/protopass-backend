from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.http import HttpResponse, JsonResponse
from rest_framework.views import APIView
from rest_framework import permissions


class EmailValidatorView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        try:
            email = request.query_params['email']
            the_id = request.query_params['id']

            validate_email(email)

            user = User.objects.get(username=email)
            if user.is_active:
                return JsonResponse({'error': 'UserIsInWrongState'}, status=403)
            if user.activation_id.activation_id == the_id:
                user.activation_id.delete()
                user.is_active = True
                user.save()
            else:
                return JsonResponse({'error': 'IdNotValid'}, status=403)
        except KeyError:
            return JsonResponse({'error': "BadInput"}, status=400)
        except User.DoesNotExist:
            return JsonResponse({'error': "UserNotExists"}, status=403)
        except ValidationError:
            return JsonResponse({'error': 'EmailNotValid'}, status=400)

        return HttpResponse()
