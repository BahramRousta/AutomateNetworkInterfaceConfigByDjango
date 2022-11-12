from django.contrib import admin
from .models import ConnectDevice, Port, Host, FireWall

admin.site.register(Host)
admin.site.register(ConnectDevice)
admin.site.register(Port)
admin.site.register(FireWall)
