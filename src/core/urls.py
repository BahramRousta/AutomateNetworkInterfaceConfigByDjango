from django.urls import path
from .views import (
    GetOSDevice,
    ScanNetwork,
    ChangeDeviceNetworkInterFace,
    ChangeDeviceIp,
    ChangeDNS,
    PingDevice,
    CheckOpenPort
)


urlpatterns = [
    path('change_device_net_intf/', ChangeDeviceNetworkInterFace.as_view(), name='change_device_net_intf'),
    path('change_ip/', ChangeDeviceIp.as_view(), name='change_ip'),
    path('change_dns/', ChangeDNS.as_view(), name='change_ip'),
    path('scan_network/', ScanNetwork.as_view(), name='scan_network'),
    path('detect_os_device/', GetOSDevice.as_view(), name='detect_os_device'),
    path('ping_device/', PingDevice.as_view(), name='ping_device'),
    path('open_port/', CheckOpenPort.as_view(), name='open_port'),
]