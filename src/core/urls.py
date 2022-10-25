from django.urls import path
from .views import (
    GetOSDevice,
    ScanNetwork,
    ChangeDeviceIp,
    PingDevice
)


urlpatterns = [
    path('change_ip_address/', ChangeDeviceIp.as_view(), name='change_ip_address'),
    path('scan_network/', ScanNetwork.as_view(), name='scan_network'),
    path('detect_os_device/', GetOSDevice.as_view(), name='detect_os_device'),
    path('ping_device/', PingDevice.as_view(), name='ping_device'),
]