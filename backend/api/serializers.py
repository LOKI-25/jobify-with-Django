from rest_framework import serializers
from .models import User, Job

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'name', 'email', 'lastName', 'location']
        extra_kwargs = {
            'id': {'read_only': True},
        }

class JobSerializer(serializers.ModelSerializer):
    createdBy = UserSerializer(read_only=True)

    class Meta:
        model = Job
        fields = ['id', 'company', 'position', 'status', 'jobType', 'jobLocation', 'createdBy', 'created_at', 'updated_at']
        extra_kwargs = {
            'id': {'read_only': True},
            'created_at': {'read_only': True},
            'updated_at': {'read_only': True},
        }
