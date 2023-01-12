from rest_framework import serializers
from .models import User, Transaction
 
            
#user serializer
class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ('id', 'username')


class TransactionSerializer(serializers.ModelSerializer):
    shared_users = serializers.SerializerMethodField()
    amount_per_person = serializers.SerializerMethodField()
    user = UserSerializer(read_only=True)

    def get_shared_users(self, transaction):
        users = UserSerializer(transaction.shared_users.all(), many=True)
        return users.data

    def get_amount_per_person(self, transaction):
        num = transaction.shared_users.all().count() + 1
        return "{:.1f}".format(transaction.total_amount / num)

    class Meta:
        model = Transaction
        fields = ('id', 'total_amount', 'user', 'category', 'shared_users','amount_per_person', 'created_at')
