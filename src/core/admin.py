from django.contrib import admin
from .models import Devices, Ports


admin.site.register(Ports)
admin.site.register(Devices)
