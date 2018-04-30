from rest_framework.authentication import TokenAuthentication


class ProtopassAuthentication(TokenAuthentication):
    keyword = 'LoginSession'
