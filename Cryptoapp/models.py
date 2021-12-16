from django.db import models

# Create your models here.
class otpuser(models.Model):
    username = models.CharField(max_length=100,primary_key=True)
    password = models.CharField(max_length=100)
    email = models.CharField(max_length=100)
    token = models.CharField(max_length=100)
    class Meta:
        verbose_name = "user"
        ordering = ['username']
    def __str__(self):
         return ' '.join([
        self.username,
        self.password,
        self.email,
        self.token,
    ])
