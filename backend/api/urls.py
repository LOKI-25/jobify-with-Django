from django.urls import path
from .views import (
    RegisterView,
    LoginView,
    UpdateUserView,
    GetCurrentUserView,
    LogoutView,
    CreateJobView,
    GetAllJobsView,
    UpdateJobView,
    DeleteJobView,
    ShowStatsView,
    CustomTokenObtainPairView,
)

urlpatterns = [
    path("token/", CustomTokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("register/", RegisterView.as_view(), name="register"),
    path("login/", LoginView.as_view(), name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("updateUser/", UpdateUserView.as_view(), name="update_user"),
    path("getCurrentUser/", GetCurrentUserView.as_view(), name="get_current_user"),
    path("add-job/", CreateJobView.as_view(), name="create_job"),
    path("jobs/", GetAllJobsView.as_view(), name="get_all_jobs"),
    path("updateJob/<int:pk>/", UpdateJobView.as_view(), name="update_job"),
    path("deleteJob/<int:pk>/", DeleteJobView.as_view(), name="delete_job"),
    path("showStats/", ShowStatsView.as_view(), name="show_stats"),
]
