from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.http import HttpResponse, JsonResponse
from rest_framework.views import APIView


class EmailValidatorView(APIView):

    def get(self, request):
        print()

        try:
            email = request.query_params['email']
            the_id = request.query_params['id']

            validate_email(email)

            user = User.objects.get(username=email)
            if user.is_active:
                return JsonResponse({'error': 'The user already registered'}, status=403)
            if user.activation_id.activation_id == the_id:
                user.activation_id.delete()
                user.is_active = True
                user.save()
            else:
                return JsonResponse({'error': 'the provided id is not valid'}, status=403)
        except KeyError as e:
            return JsonResponse({'error': "{} is missing!".format(e.args[0])}, status=400)
        except User.DoesNotExist as e:
            return JsonResponse({'error': "User does not exist!"}, status=403)
        except ValidationError as e:
            return JsonResponse({'error': e.message}, status=400)

        return HttpResponse()
