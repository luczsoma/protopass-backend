from django.contrib.auth.models import User


class AuthBackend:

    def authenticate(self, request, email=None, challenge=None):
        # TODO
        return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
