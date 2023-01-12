from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.serializers import TokenVerifySerializer, TokenRefreshSerializer
from ..serializers import UserSerializer
from django.utils.deprecation import MiddlewareMixin
from ..models import User

class CurrentUser(MiddlewareMixin):

    def process_request(self, request):
      request.currentUser = ''
      token = request.COOKIES.get('accesstoken')
      refreshtoken = request.COOKIES.get('refreshtoken')
      if not token:
          return None

      data = {'token': token}
      try:
          # check if access token is valid
          valid_data = TokenVerifySerializer().validate(data)
      except:
          # null user as access token is invalid
          try:
            new_token = TokenRefreshSerializer.validate(self, {'refresh':refreshtoken})
            token = new_token['access']
          except:     
            return None
      try:
        validated_token = JWTAuthentication.get_validated_token(self, raw_token=token)
        user = JWTAuthentication.get_user(self, validated_token=validated_token)
        request.currentUser = user
      except:
        return None
