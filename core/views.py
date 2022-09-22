from django.shortcuts import render, HttpResponse
from .utils import SSHConnect


def index(request):
    hostname = "192.168.1.85"
    return render(request, 'core/index.html', {'hostname': hostname})


def change_ip_address(request):
    if request.method == "POST":
        hostname = request.POST.get('ip_address')
        new_ip_address = request.POST.get('new_ip_address')
        username = request.POST.get('username')
        password = request.POST.get('password')

        device = SSHConnect(hostname=hostname,
                            username=username,
                            password=password)
        device.open_session()
        device.open_sftp_session()
        device.get_file(localpath='C:/Users/Berooz Stock/Desktop/SSHConnection/01-network-manager-all.yaml')
        device.modify_config(new_ip_address=f'{new_ip_address}/24',
                             localpath='C:/Users/Berooz Stock/Desktop/SSHConnection/01-network-manager-all.yaml')
        device.put_file(localpath='C:/Users/Berooz Stock/Desktop/SSHConnection/01-network-manager-all.yaml')
        device.close_sftp_session()
        device.apply_config(delay=3)
        device.close_session()
        return HttpResponse('ok')