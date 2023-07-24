from django.db import models
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.core import validators
import jwt
from datetime import datetime, timedelta

from django.contrib.auth.models import BaseUserManager


class CustomUserManager(BaseUserManager):
    def create_user(self, email, name, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")
        if not name:
            raise ValueError("The Name field must be set")
        if password is None:
            raise ValueError("The password field must be set")

        email = self.normalize_email(email)
        user = self.model(email=email, name=name, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, name, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(email, name, password, **extra_fields)


class User(AbstractUser):
    username = None
    name = models.CharField(
        max_length=20,
        validators=[
            validators.MinLengthValidator(3),
            validators.MaxLengthValidator(20),
        ],
        verbose_name="Name",
        blank=False,
        null=False,
        error_messages={
            "blank": "Name field cannot be blank.",
            "null": "Name field cannot be null.",
        },
    )
    email = models.EmailField(
        verbose_name="Email",
        unique=True,
        blank=False,
        null=False,
        error_messages={
            "blank": "Email field cannot be blank.",
            "null": "Email field cannot be null.",
            "unique": "This email is already registered.",
        },
    )
    lastName = models.CharField(
        max_length=20, default="lastName", verbose_name="Last Name"
    )
    location = models.CharField(
        max_length=20, default="my city", verbose_name="Location"
    )

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["name"]
    objects = CustomUserManager()

    def __str__(self):
        return self.email

    # def save(self, *args, **kwargs):
    #     if not self.password:
    #         raise ValueError("The Password field must be set")
    #     super().save(*args, **kwargs)

    def create_jwt(self):
        jwt_secret_key = "your_secret_key"

        # Set the JWT lifetime (e.g., 1 day)
        jwt_lifetime = 1  # in days

        # Generate the JWT payload
        payload = {
            "userId": self.id,
            "exp": datetime.utcnow() + timedelta(days=jwt_lifetime),
        }

        # Generate the JWT token
        token = jwt.encode(payload, jwt_secret_key, algorithm="HS256")
        # print(jwt.decode(token, jwt_secret_key, algorithms=["HS256"]))

        # Return the JWT token as a string

        return token

    class Meta:
        verbose_name_plural = "Users"


class Job(models.Model):
    STATUS_CHOICES = [
        ("interview", "Interview"),
        ("declined", "Declined"),
        ("pending", "Pending"),
    ]

    JOB_TYPE_CHOICES = [
        ("full-time", "Full-time"),
        ("part-time", "Part-time"),
        ("remote", "Remote"),
        ("internship", "Internship"),
    ]

    company = models.CharField(max_length=50, verbose_name="Company")
    position = models.CharField(max_length=100, verbose_name="Position")
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default="pending", verbose_name="Status"
    )
    jobType = models.CharField(
        max_length=20,
        choices=JOB_TYPE_CHOICES,
        default="full-time",
        verbose_name="Job Type",
    )
    jobLocation = models.CharField(
        max_length=100, default="my city", verbose_name="Job Location"
    )
    createdBy = models.ForeignKey(
        "User", on_delete=models.CASCADE, related_name="jobs", verbose_name="Created By"
    )
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Created At")
    updated_at = models.DateTimeField(auto_now=True, verbose_name="Updated At")

    def __str__(self):
        return f"{self.position} at {self.company}"

    class Meta:
        verbose_name_plural = "Jobs"
