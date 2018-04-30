from django.conf.urls import url
from protopass_auth.views.authentication import RegisterView, ChallengeView, AuthenticateView, LogoutView, \
    ChangePasswordView, ResetPasswordView
from protopass_auth.views.email_validator import EmailValidatorView

urlpatterns = [
    url(r'register$', RegisterView.as_view()),
    url(r'validate$', EmailValidatorView.as_view()),
    url(r'challenge$', ChallengeView.as_view()),
    url(r'authenticate$', AuthenticateView.as_view()),
    url(r'logout$', LogoutView.as_view()),
    url(r'changePassword$', ChangePasswordView.as_view()),
    url(r'resetPasswordRequest$', ResetPasswordView.as_view()),
    url(r'resetPassword$', ResetPasswordView.as_view()),
]