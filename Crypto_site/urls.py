"""Crypto_site URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
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
from Cryptoapp import views
urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.loginuser, name='login'),
    path('logout/', views.logoutuser, name='logoutuser'),
    path('home/', views.home, name='home'),
    path('Cipher/',views.choix,name='Cipher'),
    path('Cesar/',views.Ceasar,name='Ceasar'),
    path('Homophonic/',views.Homophonic,name='Homophonic'),
    path('CBC/',views.CBC,name='CBC'),
    path('Hill/',views.Hill,name='Hill'),
    path('Vigenere/',views.Vigenere,name='Vigenere'),
    path('Vernam/',views.Vernam,name='Vernam'),
    path('Permutation/',views.Permutation,name='Permutation'),
    path('ECB/',views.ECB,name='ECB'),
    path('CTR/',views.CTR,name='CTR'),
    path('RC4/',views.RC4,name='RC4'),
    path('signup/', views.signup, name='signup'),
]
