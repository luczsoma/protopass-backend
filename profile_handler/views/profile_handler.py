import base64
import binascii

from django.core.exceptions import ObjectDoesNotExist
from django.http import JsonResponse, HttpResponse
from rest_framework.views import APIView

from profile_handler.models.protopass_profile import ProtopassProfile


class UploadProfileView(APIView):

    def put(self, request):
        try:
            profile_data = base64.b64decode(request.data['encryptedUserProfile'])
            container_key_salt = base64.b64decode(request.data['containerKeySalt'])
            init_vector = base64.b64decode(request.data['initializationVector'])
        except KeyError as e:
            return JsonResponse({'error': "{} is missing!".format(e.args[0])}, status=400)
        except binascii.Error:
            return JsonResponse({'error': "base64format error"}, status=400)

        try:
            profile = request.user.protopass_profile

            if profile.container_key_salt == container_key_salt or profile.init_vector == init_vector:
                return JsonResponse({'error': "salt/initvector not fresh!"}, status=412)
        except ObjectDoesNotExist as e:
            profile = ProtopassProfile.objects.create(user=request.user)

        profile.profile_data = profile_data
        profile.container_key_salt = container_key_salt
        profile.init_vector = init_vector

        profile.save()

        return HttpResponse()


class DownloadProfileView(APIView):

    def get(self, request):
        profile = request.user.protopass_profile
        if profile is None:
            return JsonResponse({'error': "Profile not found!"}, status=404)

        result = {}
        result['encryptedUserProfile'] = base64.b64encode(profile.profile_data).decode('utf-8')
        result['containerKeySalt'] = base64.b64encode(profile.container_key_salt).decode('utf-8')
        result['initializationVector'] = base64.b64encode(profile.init_vector).decode('utf-8')

        return JsonResponse(result)
