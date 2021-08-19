from django.db import models


# Create your models here.
class UserInfo(models.Model):
    visitorId = models.CharField(max_length=50)
    hash_fingerprint = models.CharField(max_length=50)
    hash_canvas_fingerprint = models.CharField(max_length=50)
    user_ip = models.CharField(max_length=15)
