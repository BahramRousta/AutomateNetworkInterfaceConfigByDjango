from django.urls import path
from .views import (
    GetOSDevice,
    ScanNetwork,
    ChangeDeviceNetworkInterFace,
    ChangeDeviceIp,
    ChangeDNS,
    PingDevice,
    CheckPort,
    AddSSHKey,
    FireWallStatus,
    FireWallDefaultPolicy,
    FindDeviceNetworkConnection,
)


urlpatterns = [
    path('add_ssh_key/', AddSSHKey.as_view(), name='add_ssh_key'),
    path('find_net_connection/', FindDeviceNetworkConnection.as_view(), name='find_net_connection'),
    path('change_device_net_intf/', ChangeDeviceNetworkInterFace.as_view(), name='change_device_net_intf'),
    path('change_ip/', ChangeDeviceIp.as_view(), name='change_ip'),
    path('change_dns/', ChangeDNS.as_view(), name='change_ip'),
    path('scan_network/', ScanNetwork.as_view(), name='scan_network'),
    path('detect_os_device/', GetOSDevice.as_view(), name='detect_os_device'),
    path('ping_device/', PingDevice.as_view(), name='ping_device'),
    path('open_port/', CheckPort.as_view(), name='open_port'),
    path('enable_firewall/', FireWallStatus.as_view(), name='enable_firewall'),
    path('disable_firewall/', FireWallStatus.as_view(), name='disable_firewall'),
    path('get_firewall_status/', FireWallStatus.as_view(), name='get_firewall_status'),
    path('reset_firewall/', FireWallStatus.as_view(), name='reset_firewall'),
    path('firewall_default_policy/', FireWallDefaultPolicy.as_view(), name='firewall_default_policy'),
    path('limit_port/', FireWallStatus.as_view(), name='limit_port')
]