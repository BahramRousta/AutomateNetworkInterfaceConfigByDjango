from django.urls import path
from .views import index, change_ip_address


urlpatterns = [
    path('', index, name='index'),
    path('change_ip_address/', change_ip_address, name='change_ip_address'),
]