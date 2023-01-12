from django.urls import path, include
from .views import RegisterAPI, UserAPI, AddFriendsAPI, GetFriendsAPI, AddTransactionAPI, GetTransactionsAPI, DeleteTransactionAPI

urlpatterns = [
    path('register', RegisterAPI.as_view(), name='register'), 
    path('currentuser', UserAPI.as_view(), name='current_user'),
    path('add-friends', AddFriendsAPI.as_view(), name='AddFriendsAPI'),
    path('get-friends', GetFriendsAPI.as_view(), name='GetFriendsAPI'),
    path('add-transaction', AddTransactionAPI.as_view(), name='AddTransactionAPI'),
    path('get-transactions', GetTransactionsAPI.as_view(), name='GetTransactionsAPI'),
    path('transaction/<int:pk>', DeleteTransactionAPI.as_view(), name='DeleteTransactionAPI'),
]

