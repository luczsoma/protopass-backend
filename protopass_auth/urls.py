from django.conf.urls import url
from protopass_auth.views.authentication import RegisterView
from protopass_auth.views.email_validator import EmailValidatorView

urlpatterns = [
    url(r'register$', RegisterView.as_view()),
    url(r'validate$', EmailValidatorView.as_view()),
]