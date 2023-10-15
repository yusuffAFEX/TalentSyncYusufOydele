from django.contrib import admin
from django.urls import path

from blog.views import CreateUserAPIView, LoginAPIView, ListCreateBlogAPIView, RetrieveUpdateDestroyBlogAPIView

urlpatterns = [
    path('register', CreateUserAPIView.as_view()),
    path('login', LoginAPIView.as_view()),
    path('blogs', ListCreateBlogAPIView.as_view()),
    path('blogs/<slug:slug>', RetrieveUpdateDestroyBlogAPIView.as_view()),
]