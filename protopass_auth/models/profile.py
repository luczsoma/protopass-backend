from django.contrib.auth import get_user_model
from django.db import models


class Profile(models.Model):
    user = models.OneToOneField(get_user_model(), on_delete=models.CASCADE, related_name='profile')

    verifier = models.CharField(max_length=1000, null=False, blank=False)
    salt = models.CharField(max_length=1000, null=False, blank=False)

