from django.conf.urls import url
from protopass_auth.views.authentication import RegisterView, ChallengeView, AuthenticateView
from protopass_auth.views.email_validator import EmailValidatorView

urlpatterns = [
    url(r'register$', RegisterView.as_view()),
    url(r'validate$', EmailValidatorView.as_view()),
    url(r'challenge$', ChallengeView.as_view()),
    url(r'authenticate$', AuthenticateView.as_view()),
]