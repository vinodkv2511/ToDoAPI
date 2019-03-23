from django.db import models
from django.conf import settings


class TaskList(models.Model):

    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=50)
    description = models.TextField()


class Task(models.Model):

    id = models.AutoField(primary_key=True)
    list = models.ForeignKey('TaskList', on_delete=models.CASCADE)  # Foreign key relation to List
    name = models.CharField(max_length=50)
    done = models.BooleanField(default=False)
    description = models.TextField()


class ListAccess(models.Model):

    # Foreign key relation to user model
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)

    # Foreign key relation to List
    list = models.ForeignKey('TaskList', on_delete=models.CASCADE)

    # this field provides access level of a user on a list, possible values owner, guest
    role = models.CharField(max_length=5)


