from django.contrib import admin
from .models import ConnectDevice, Port, Host

admin.site.register(Host)
admin.site.register(ConnectDevice)
admin.site.register(Port)
