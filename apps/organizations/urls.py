from django.urls import path
from . import views

app_name = "organizations"
urlpatterns = [
    path("", views.index, name="index"),
    path("profile/", views.profile, name="profile"),
    path("my-profile/", views.my_profile, name="my_profile"),
    path("experience-mode/", views.set_experience_mode, name="set_experience_mode"),
    path("about/", views.about_aegisflow, name="about"),
    path("agent/", views.get_agent, name="get_agent"),
    path("assistant/", views.app_assistant, name="app_assistant"),
    path("assistant/ask/", views.ask_app_assistant, name="ask_app_assistant"),
]
