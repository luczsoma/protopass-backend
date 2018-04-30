from django.contrib.auth import get_user_model
from django.db import models


class Profile(models.Model):
    user = models.OneToOneField(get_user_model(), on_delete=models.CASCADE, related_name='profile')

    verifier = models.BinaryField(null=False, blank=False)
    salt = models.BinaryField(null=False, blank=False)

    client_challenge = models.BinaryField()
    server_challenge_id = models.BinaryField()