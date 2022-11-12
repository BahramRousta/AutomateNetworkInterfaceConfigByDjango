from django.contrib import admin
from .models import ConnectDevice, PortLog, Host, FireWall, Port

admin.site.register(Host)
admin.site.register(ConnectDevice)
admin.site.register(PortLog)
admin.site.register(FireWall)
admin.site.register(Port)
