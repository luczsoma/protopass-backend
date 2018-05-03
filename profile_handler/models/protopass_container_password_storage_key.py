from django.db import models
from django.contrib.auth.models import User


class ProtopassContainerPasswordStorageKey(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='container_password_storage_key')

    key = models.CharField(max_length=128)
