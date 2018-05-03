import base64
import binascii

from django.core.exceptions import ObjectDoesNotExist
from django.http import JsonResponse, HttpResponse
from django.utils.crypto import get_random_string
from rest_framework.views import APIView
from rest_framework import permissions

from profile_handler.models.protopass_profile import ProtopassProfile
from profile_handler.models.protopass_container_password_storage_key import ProtopassContainerPasswordStorageKey


class UploadProfileView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def put(self, request):
        try:
            profile_data = base64.b64decode(request.data['encryptedUserProfile'])
            container_key_salt = base64.b64decode(request.data['containerKeySalt'])
            init_vector = base64.b64decode(request.data['initializationVector'])
        except KeyError:
            return JsonResponse({'error': "BadInput"}, status=400)
        except binascii.Error:
            return JsonResponse({'error': "BadInput"}, status=400)

        try:
            profile = request.user.protopass_profile

            if profile.init_vector == init_vector:
                return JsonResponse({'error': "InitializationVectorNotFresh"}, status=412)

            if profile.container_key_salt == container_key_salt:
                return JsonResponse({'error': "ContainerKeySaltNotFresh"}, status=412)

        except ObjectDoesNotExist:
            profile = ProtopassProfile.objects.create(user=request.user)

        profile.profile_data = profile_data
        profile.container_key_salt = container_key_salt
        profile.init_vector = init_vector

        profile.save()

        return HttpResponse()


class DownloadProfileView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        try:
            profile = request.user.protopass_profile
        except ObjectDoesNotExist:
            return JsonResponse({'error': "UserProfileNotFound"}, status=404)

        if profile is None:
            return JsonResponse({'error': "UserProfileNotFound"}, status=404)

        result = {}
        result['encryptedUserProfile'] = base64.b64encode(profile.profile_data).decode('utf-8')
        result['containerKeySalt'] = base64.b64encode(profile.container_key_salt).decode('utf-8')
        result['initializationVector'] = base64.b64encode(profile.init_vector).decode('utf-8')

        return JsonResponse(result)


class DownloadStorageKeyView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        force_fresh = request.query_params.get('forceFresh')
        if force_fresh is None:
            force_fresh = 'false'

        random = get_random_string(length=128)

        try:
            container_password_storage_key = request.user.container_password_storage_key
        except ObjectDoesNotExist:
            container_password_storage_key = ProtopassContainerPasswordStorageKey.objects.create(user=request.user)
            container_password_storage_key.key = random
            container_password_storage_key.save()

            return JsonResponse({'containerPasswordStorageKey': container_password_storage_key.key})

        if force_fresh == 'true':
            container_password_storage_key.key = random
            container_password_storage_key.save()
            return JsonResponse({'containerPasswordStorageKey': container_password_storage_key.key})

        elif force_fresh == 'false':
            return JsonResponse({'containerPasswordStorageKey': container_password_storage_key.key})
