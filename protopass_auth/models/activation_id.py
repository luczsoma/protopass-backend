from django.contrib.auth import get_user_model
from django.db import models


class ActivationId(models.Model):
    user = models.OneToOneField(get_user_model(), on_delete=models.CASCADE, related_name='activation_id')
    activation_id = models.CharField(max_length=128)
