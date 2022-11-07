from django.urls import path
from .views import (
    GetOSDevice,
    ScanNetwork,
    ChangeDeviceNetworkInterFace,
    ChangeDeviceIp,
    ChangeDNS,
    ChangeGetWay,
    PingDevice,
    CheckPort,
    AddSSHKey,
    FireWall,
    FindDeviceNetworkConnection
)


urlpatterns = [
    path('add_ssh_key/', AddSSHKey.as_view(), name='add_ssh_key'),
    path('find_net_connection/', FindDeviceNetworkConnection.as_view(), name='find_net_connection'),
    path('change_device_net_intf/', ChangeDeviceNetworkInterFace.as_view(), name='change_device_net_intf'),
    path('change_ip/', ChangeDeviceIp.as_view(), name='change_ip'),
    path('change_dns/', ChangeDNS.as_view(), name='change_ip'),
    path('change_getway/', ChangeGetWay.as_view(), name='change_getway'),
    path('scan_network/', ScanNetwork.as_view(), name='scan_network'),
    path('detect_os_device/', GetOSDevice.as_view(), name='detect_os_device'),
    path('ping_device/', PingDevice.as_view(), name='ping_device'),
    path('open_port/', CheckPort.as_view(), name='open_port'),
    path('enable_firewall/', FireWall.as_view(), name='enable_firewall'),
]