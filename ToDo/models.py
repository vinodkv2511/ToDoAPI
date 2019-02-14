from django.db import models
from django.conf import settings


class List(models.Model):

    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=50)
    description = models.TextField()


class Task(models.Model):

    id = models.AutoField(primary_key=True)
    list = models.ForeignKey('List', on_delete=models.CASCADE)  # Foreign key relation to List
    name = models.CharField(max_length=50)
    description = models.TextField()


class ListAccess(models.Model):

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE
        )  # Foreign key relation to user model

    list = models.ForeignKey(
        'List', 
        on_delete=models.CASCADE
        )  # Foreign key relation to List

    role = models.CharField(  # this field provides access level of a user on a list
        max_length=5,
        choices=(
            ('owner', 'owner'),
            ('guest', 'guest')
        )
    )


