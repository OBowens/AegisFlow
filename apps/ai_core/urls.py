from django.urls import path

from . import views

app_name = "ai_core"
urlpatterns = [
    path("reveal/<int:pk>/", views.reveal_alias, name="reveal_alias"),
]
