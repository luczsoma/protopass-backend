from django.db import models
from django.contrib.auth.models import User


class ProtopassProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='protopass_profile')

    storage_key = models.TextField(null=False)
    profile_data = models.BinaryField()
    container_key_salt = models.BinaryField()
    init_vector = models.BinaryField()
