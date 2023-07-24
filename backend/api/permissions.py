from rest_framework.permissions import BasePermission

class IsJobCreator(BasePermission):
    def has_object_permission(self, request, view, obj):
        return obj.createdBy == request.user
