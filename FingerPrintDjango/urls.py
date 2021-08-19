from django.urls import path, include
from FingerPrintDjango import views

urlpatterns = [
    path('', views.login)
]
