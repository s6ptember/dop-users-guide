from django.db import models
from django.contrib.auth.models import AbstractUser, \
    BaseUserManager
from django.utils.html import strip_tags


class CustomUserManager(BaseUserManager):
    def create_user(self, email, first_name, last_name, password=None, **extra_fields):
        if not email:
            raise ValueError('The email field must be set.')
        email = self.normalize_email(email)
        user = self.model(email=email, first_name=first_name,
                          last_name=last_name, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    
    def create_superuser(self, email, first_name, last_name, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, first_name, last_name, password, **extra_fields)


class CustomUser(AbstractUser):
    email = models.EmailField(unique=True, max_length=66)
    first_name = models.CharField(max_length=66)
    last_name = models.CharField(max_length=66)
    address1 = models.CharField(max_length=128, blank=True, null=True)
    address2 = models.CharField(max_length=128, blank=True, null=True)
    city = models.CharField(max_length=128, blank=True, null=True)
    country = models.CharField(max_length=128, blank=True, null=True)
    province = models.CharField(max_length=128, blank=True, null=True)
    postal_code = models.CharField(max_length=20, blank=True, null=True)
    phone = models.CharField(max_length=15, blank=True, null=True)
    marketing_consent1 = models.BooleanField(default=False)
    marketing_consent2 = models.BooleanField(default=False)

    username = models.CharField(max_length=150, unique=True, null=True, blank=True)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']


    def __str__(self):
        return self.email
    

    def clean(self):
        for field in ['address1', 'address2', 'city', 'country', 'province',
                          'postal_code', 'phone']:
            value = getattr(self, field)
            if value:
                setattr(self, field, strip_tags(value))