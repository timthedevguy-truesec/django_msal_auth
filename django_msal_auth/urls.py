"""Django URL patterns for MSAL authentication."""

from django.urls import path

from . import views

urlpatterns = [
    path('to-auth-redirect/', views.to_auth_redirect, name='msal_auth_redirect'),
    path('from-auth-redirect/', views.from_auth_redirect, name='msal_auth_callback'),
    path('logoff/', views.signout, name='msal_logoff'),
]
