from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone

CATEGORY_CHOICES = (
    ('movie', 'movie'),
    ('food', 'food'),
    ('medical', 'medical')
)


class User(AbstractUser):
    name = models.CharField(max_length=50, blank=True)
    friends = models.ManyToManyField('self', related_name='friends_of', blank=True)

    def __str__(self):
        return self.username
    
class Transaction(models.Model):
    user = models.ForeignKey(User, related_name='transactions', null=True, on_delete=models.CASCADE)
    content = models.TextField(blank=True, default='', max_length= 600)
    shared_users = models.ManyToManyField(User, related_name='owe_transactions')
    total_amount = models.PositiveIntegerField(default=0)
    category = models.CharField(choices=CATEGORY_CHOICES, blank=True, default='', max_length= 50)
    created_at = models.DateTimeField(auto_now_add=True)
