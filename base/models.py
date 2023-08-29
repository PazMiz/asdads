from django.db import models
from django.contrib.auth.models import User
from django import forms
from django.template.defaultfilters import truncatechars 
from django.utils.safestring import mark_safe
from django.contrib.auth.models import AbstractUser

        
class Category(models.Model):
    name = models.CharField(max_length=50)

    def __str__(self):
        return self.name

class Product(models.Model):
    category = models.ForeignKey(Category, on_delete=models.CASCADE, null=True)
    image = models.ImageField(upload_to='photos', null=True, blank=True, default='/placeholder.png')
    desc = models.CharField(max_length=50, null=True, blank=True)
    price = models.IntegerField()
    createdTime = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.desc
    
    @property
    def short_description(self):
        return truncatechars(self.desc, 20)

    def admin_photo(self):
        return mark_safe('<img src="{}" width="100" />'.format(self.image.url))

    admin_photo.short_description = 'Image'
    admin_photo.allow_tags = True

    def __str__(self):
        return f'{self.desc} {self.price} {self.image}'
    
    

class BlacklistedToken(models.Model):
    token = models.TextField(unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]



class Topic(models.Model):
    topic = models.CharField(max_length=255)
    author = models.CharField(max_length=255)
    text = models.TextField(default='default_text')  # Add a default value

    def __str__(self):
        return self.topic

