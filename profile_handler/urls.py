from django.conf.urls import url
from profile_handler.views.profile_handler import UploadProfileView, DownloadProfileView, DownloadStorageKeyView

urlpatterns = [
    url(r'uploadUserProfile$', UploadProfileView.as_view()),
    url(r'downloadUserProfile$', DownloadProfileView.as_view()),
    url(r'getStorageKey$', DownloadStorageKeyView.as_view()),
]