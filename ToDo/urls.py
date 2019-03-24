"""ToDo URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.1/topics/http/urls/
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
from django.urls import path, re_path
from . import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('hello_world', views.HelloWorld.as_view()),
    # Paths for login
    re_path(r'^login(?:\/)?$', views.Login.as_view()),
    re_path(r'^login/refresh(?:\/)?$', views.LoginRefresh.as_view()),
    path('login/register', views.Register.as_view()),

    # Paths for Lists
    re_path(r'^lists/add(?:\/)?$', views.ListAdd.as_view()),
    re_path(r'^lists/list(?:\/)?$', views.ListFetch.as_view()),
    re_path(r'^tasks/add(?:\/)?$', views.TaskAdd.as_view()),
    re_path(r'^tasks/list$', views.TaskFetch.as_view()),
    re_path(r'^tasks/task/update_status(?:\/)?$', views.TaskStatusSet.as_view()),
]
