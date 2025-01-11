"""
URL configuration for linkgui project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from link.views import CustomLoginView, dashboard, logout_view, contact, download_logfile, ping, traceroute, poweroff, restart
from django.views.generic import RedirectView
urlpatterns = [
   
    path('login/', CustomLoginView.as_view(), name='login'),
    path('dashboard/', dashboard, name='dashboard'),
    path('logout/', logout_view, name='logout'),
    path('contact/<str:tab_name>/', contact, name='contact'),
    path('accounts/profile/', RedirectView.as_view(pattern_name='dashboard', permanent=True)),    
    path('download-log/', download_logfile, name='download_logfile'),
    path('ping', ping, name='ping'),
    path('traceroute', traceroute, name='traceroute'),
    path('poweroff', poweroff, name='poweroff'),
    path('restart', restart, name='restart'),

]
