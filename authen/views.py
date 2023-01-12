from django.shortcuts import render
from rest_framework import generics, permissions, status
from rest_framework_simplejwt.tokens import SlidingToken, RefreshToken
from rest_framework_simplejwt.views import token_refresh_sliding
from rest_framework_simplejwt.serializers import TokenVerifySerializer, TokenRefreshSerializer, TokenRefreshSlidingSerializer 
from rest_framework_simplejwt.authentication import JWTAuthentication
from .models import User, Transaction
from rest_framework.response import Response
from .serializers import UserSerializer, TransactionSerializer

# Register API
class RegisterAPI(generics.GenericAPIView):
    serializer_class = UserSerializer

    def post(self, request, *args, **kwargs):
        if not request.data.keys() >= {'password', 'username'}:
            return Response({
                'errors': [{ 'message':  'please provide all password, username' }]
            }, status=status.HTTP_400_BAD_REQUEST)
        user = User.objects.filter(username__iexact=request.data['username']).first()
        if user:
            if user.is_active=='True':
                if user.check_password(request.data['password']):
                    pass
                else:
                    return Response({
                        'errors': [{ 'message':  'Wrong password.' }]
                    }, status=status.HTTP_400_BAD_REQUEST)
            else:
                user.is_active = True
                user.set_password(request.data['password'])
                user.save()
        else:
            user = User.objects.create_user(
                    username=request.data['username'], 
                    password=request.data['password'], 
                    is_active=True,
                )
        response = Response()
        token = RefreshToken.for_user(user)
        response.set_cookie(key='refreshtoken', value=str(token), secure=False, httponly=True, samesite='Lax', max_age=22000000)
        response.set_cookie(key='accesstoken', value=str(token.access_token), secure=False, httponly=True, samesite='Lax', max_age=22000000)
        response.data = {
            "user": UserSerializer(user).data,
        }
        return response 




class UserAPI(generics.GenericAPIView):

    def get(self, request, *args, **kwargs):
        # try:
            refreshtoken = request.COOKIES.get('refreshtoken')
            token = request.COOKIES.get('accesstoken')
            new_token = None
            if not token:
                return Response({
                    'user': None
                })
            data = {'token': token}
            # check if access token is valid
            try:
                valid_data = TokenVerifySerializer().validate(data)
            except:
                try:
                    new_token = TokenRefreshSerializer.validate(self, {'refresh':refreshtoken})
                    token = new_token['access']
                except:
                    return Response({
                        'user': None
                    })
            try:
                validated_token = JWTAuthentication.get_validated_token(self, raw_token=token)
                user = JWTAuthentication.get_user(self, validated_token=validated_token)
            except:
                return Response({
                    'user': None
                })
            response = Response()
            if new_token:
                response.set_cookie(key='refreshtoken', value=str(new_token['refresh']), secure=os.getenv('SECURE', False), httponly=True, samesite=os.getenv('SAME_SITE'), max_age=22000000, domain=os.getenv('COOKIE_DOMAIN'))
                response.set_cookie(key='accesstoken', value=str(token), secure=os.getenv('SECURE', False), httponly=True, samesite=os.getenv('SAME_SITE'), max_age=22000000, domain=os.getenv('COOKIE_DOMAIN'))
            response.data = {
                "user": user.username
            }
            return response

        
     
class AddFriendsAPI(generics.GenericAPIView):

    def post(self, request, *args, **kwargs):
        if not request.currentUser:
            return Response({
                'errors': [{ 'message':  'please login' }]
            }, status=status.HTTP_400_BAD_REQUEST)
        if not request.data.keys() >= {'username_list'}:
            return Response({
                'errors': [{ 'message':  'please provide username_list' }]
            }, status=status.HTTP_400_BAD_REQUEST)
        username_list = request.data['username_list'].split(',')
        for username in username_list:
            username = username.strip()
            user = User.objects.filter(username__iexact=username).first()
            if not user:
                user = User.objects.create_user(
                    username=username, 
                    # password=, 
                    is_active=False,
                )
            request.currentUser.friends.add(user)
        return Response({
            'message': 'Friends added'
        })


    
class GetFriendsAPI(generics.GenericAPIView):
    serializer_class = UserSerializer

    def get(self, request, *args, **kwargs):
        if not request.currentUser:
            return Response({
                'errors': [{ 'message':  'please login' }]
            }, status=status.HTTP_400_BAD_REQUEST)
        friends = request.currentUser.friends.all().order_by('id')
        serializer = self.get_serializer(
            friends, 
            many=True,
        )
        return Response(serializer.data)



class AddTransactionAPI(generics.GenericAPIView):

    def post(self, request, *args, **kwargs):
        if not request.currentUser:
            return Response({
                'errors': [{ 'message':  'please login' }]
            }, status=status.HTTP_400_BAD_REQUEST)
        if not request.data.keys() >= {'username_list','amount','category'}:
            return Response({
                'errors': [{ 'message':  'please provide username_list, amount, category' }]
            }, status=status.HTTP_400_BAD_REQUEST)
        
        transaction = Transaction.objects.create(
            user=request.currentUser,
            total_amount=int(request.data['amount']),
            category=request.data['category']
        )
        username_list = request.data['username_list'].split(',')
        for username in username_list:
            username = username.strip()
            user = User.objects.filter(username__iexact=username).first()
            if not user:
                user = User.objects.create_user(
                    username=username, 
                    is_active=False,
                )
            transaction.shared_users.add(user)
        return Response({
            'message': 'Transaction added'
        })
        

    def put(self, request, *args, **kwargs):
        if (not request.currentUser):
            return Response({
                'errors': [{ 'message':  'Login Please' }]
            }, status=status.HTTP_400_BAD_REQUEST)
        if not request.data.keys() >= {'username_list','amount','category','id'}:
            return Response({
                'errors': [{ 'message':  'please provide username_list, amount, category, id' }]
            }, status=status.HTTP_400_BAD_REQUEST)
        
        transaction = Transaction.objects.filter(
            id=request.data['id']
        ).first()
        if (request.currentUser != transaction.user):
            return Response({
                'errors': [{ 'message':  'Not allowed' }]
            }, status=status.HTTP_400_BAD_REQUEST)
        transaction.total_amount = int(request.data['amount'])
        transaction.category=request.data['category']
        transaction.shared_users.clear()
        username_list = request.data['username_list'].split(',')
        for username in username_list:
            username = username.strip()
            user = User.objects.filter(username__iexact=username).first()
            if not user:
                user = User.objects.create_user(
                    username=username, 
                    is_active=False,
                )
            transaction.shared_users.add(user)
        transaction.save()
        return Response({
            'message': 'Transaction updated'
        })
        


class DeleteTransactionAPI(generics.GenericAPIView):

    def delete(self, request, pk, format=None):
        if (not request.currentUser):
            return Response({
                'errors': [{ 'message':  'Login Please' }]
            }, status=status.HTTP_400_BAD_REQUEST)
        if not pk:
            return Response({
                'errors': [{ 'message':  'please provide id' }]
            }, status=status.HTTP_400_BAD_REQUEST)
        
        transaction = Transaction.objects.filter(
            id=pk
        ).first()
        if (request.currentUser != transaction.user):
            return Response({
                'errors': [{ 'message':  'Not allowed' }]
            }, status=status.HTTP_400_BAD_REQUEST)
        transaction.delete()
        return Response({
            'message': 'Transaction deleted'
        })
    


class GetTransactionsAPI(generics.GenericAPIView):
    serializer_class = TransactionSerializer

    def get(self, request, *args, **kwargs):
        if not request.currentUser:
            return Response({
                'errors': [{ 'message':  'please login' }]
            }, status=status.HTTP_400_BAD_REQUEST)
        trans = self.get_serializer(
            request.currentUser.transactions, 
            many=True,
        )
        owe_trans = self.get_serializer(
            request.currentUser.owe_transactions, 
            many=True,
        )
        return Response({
            'transactions': trans.data,
            'owe_transactions': owe_trans.data,
        })
