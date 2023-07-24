from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist
from .serializers import UserSerializer, JobSerializer
import datetime
from .models import Job
from django.contrib.auth import authenticate
from .permissions import IsJobCreator
from rest_framework.permissions import AllowAny
from django.db.models import Count
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication

User = get_user_model()


class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


from rest_framework_simplejwt.views import TokenObtainPairView


class CustomTokenObtainPairView(TokenObtainPairView):
    # Add custom claims to the token if needed
    def get_token(self, user):
        token = super().get_token(user)
        # Add custom claims to the token payload
        token["user_id"] = user.id
        # Add more custom claims here as needed
        return token


class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, format=None):
        email = request.data.get("email")
        password = request.data.get("password")
        user = authenticate(email=email, password=password)

        if user is not None:
            serializer = UserSerializer(user)
            token = RefreshToken.for_user(user)
            data = serializer.data
            data["tokens"] = {"refresh": str(token), "access": str(token.access_token)}
            data["location"] = user.location
            response_data = {
                "user": data,
                "location": user.location,
            }

            response = Response(response_data, status=status.HTTP_200_OK)

            response.set_cookie(
                "token", token.access_token, httponly=True
            )  # Attach the JWT token to the cookie.
            print("response", response)
            return response
        return Response(
            {"error": "Invalid Credentials"}, status=status.HTTP_401_UNAUTHORIZED
        )


class UpdateUserView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request):
        user = request.user
        serializer = UserSerializer(user, data=request.data)
        if serializer.is_valid():
            serializer.save()
            data=serializer.data
            data["location"] = user.location
            response_data = {
                "user": data,
                "location": user.location,
            }

            response = Response(response_data, status=status.HTTP_200_OK)
            return response
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GetCurrentUserView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(
        self,
        request,
    ):
        print("get current user/////////")
        print(request)
        user = request.user
        serializer = UserSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)


class LogoutView(APIView):
    def get(self, request):
        response = Response({"msg": "User logged out!"}, status=status.HTTP_200_OK)
        response.delete_cookie("token")  # Delete the JWT token cookie.
        return response


class CreateJobView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        serializer = JobSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(createdBy=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GetAllJobsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        status_param = request.query_params.get("status", "all")
        jobType_param = request.query_params.get("jobType", "all")
        sort_param = request.query_params.get("sort", "")
        search_param = request.query_params.get("search", "")

        query_object = {"createdBy": request.user}

        if status_param != "all":
            query_object["status"] = status_param

        if jobType_param != "all":
            query_object["jobType"] = jobType_param

        if search_param:
            query_object["position__icontains"] = search_param

        jobs = Job.objects.filter(**query_object)

        if sort_param == "latest":
            jobs = jobs.order_by("-created_at")
        elif sort_param == "oldest":
            jobs = jobs.order_by("created_at")
        elif sort_param == "a-z":
            jobs = jobs.order_by("position")
        elif sort_param == "z-a":
            jobs = jobs.order_by("-position")

        page = int(request.query_params.get("page", 1))
        limit = int(request.query_params.get("limit", 10))
        start_index = (page - 1) * limit
        end_index = page * limit
        total_jobs = jobs.count()
        total_pages = (total_jobs + limit - 1) // limit

        jobs = jobs[start_index:end_index]
        serializer = JobSerializer(jobs, many=True)
        return Response(
            {
                "jobs": serializer.data,
                "totalJobs": total_jobs,
                "numOfPages": total_pages,
            },
            status=status.HTTP_200_OK,
        )


class UpdateJobView(APIView):
    permission_classes = [IsAuthenticated, IsJobCreator]

    def patch(self, request, pk):
        try:
            job = Job.objects.get(pk=pk)
        except ObjectDoesNotExist:
            return Response(
                {"error": f"Job with id {pk} not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        serializer = JobSerializer(job, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class DeleteJobView(APIView):
    permission_classes = [IsAuthenticated, IsJobCreator]

    def delete(self, request, pk, format=None):
        try:
            job = Job.objects.get(pk=pk)
        except ObjectDoesNotExist:
            return Response(
                {"error": f"Job with id {pk} not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        job.delete()
        return Response({"msg": "Success! Job removed"}, status=status.HTTP_200_OK)


class ShowStatsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        stats = (
            Job.objects.filter(createdBy=request.user)
            .values("status")
            .annotate(count=Count("status"))
        )
        stats_dict = {item["status"]: item["count"] for item in stats}
        default_stats = {
            "pending": stats_dict.get("pending", 0),
            "interview": stats_dict.get("interview", 0),
            "declined": stats_dict.get("declined", 0),
        }

        monthly_applications = (
            Job.objects.filter(createdBy=request.user)
            .values("created_at__year", "created_at__month")
            .annotate(count=Count("id"))
            .order_by("-created_at__year", "-created_at__month")[:6]
        )
        monthly_applications = [
            {
                "date": self.format_date(
                    item["created_at__year"], item["created_at__month"]
                ),
                "count": item["count"],
            }
            for item in monthly_applications
        ]

        return Response(
            {
                "defaultStats": default_stats,
                "monthlyApplications": monthly_applications,
            },
            status=status.HTTP_200_OK,
        )

    def format_date(self, year, month):
        date_object = datetime.datetime(year, month, 1)
        formatted_date = date_object.strftime("%b %Y")
        return formatted_date
