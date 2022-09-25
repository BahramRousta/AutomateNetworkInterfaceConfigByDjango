from typing import Tuple, Any

import nmap
from django.shortcuts import render, HttpResponse
from .utils import SSHConnect
from .models import DeviceIpAddress


def index(request):
    hostname = "192.168.1.85"
    return render(request, 'core/index.html', {'hostname': hostname})


def scan_network(request):
    global new_device
    nm = nmap.PortScanner()
    nm.scan(arguments='-sn 192.168.1.1/24')
    ip_address = nm.all_hosts()

    hosts_name = []
    host_name = [(x, nm[x]['hostnames'][0]['name']) for x in nm.all_hosts()]
    for hostname in host_name:
        hosts_name.append(hostname[1])

    hosts_status = []
    host_status = [(y, nm[y]['status']["state"]) for y in nm.all_hosts()]
    for status in host_status:
        hosts_status.append(status[1])

    devices_log = list(zip(ip_address, hosts_name, hosts_status))
    for device in devices_log:
        new_device = DeviceIpAddress.objects.create(ip_address=device[0],
                                                    host_name=device[1],
                                                    status=device[2])
    rendred_device = DeviceIpAddress.objects.filter(status="up")
    return render(request, 'core/scan_network.html', {"devices": rendred_device})


# def scan_network(request):
#     device = SSHConnect(username='bahram',
#                         password='458000',
#                         hostname='192.168.1.51')
#     remote = device.open_session()
#     cmd = remote.invoke_shell()
#     cmd.send(f'nmap -sn 192.168.1.1/24\n')
#     time.sleep(5)
#     output = cmd.recv(50000).decode()
#     print(output)
#     device.close_session()
#
#     machine = []
#     virtual_machine = []
#     for line in output.split('\r'):
#         if "Nmap scan report for 192.168.1." in line:
#             machine.append(line)
#         elif "virtual-machine (192.168.1." in line:
#             virtual_machine.append(line)
#
#     virtual_machine_ip_address = []
#     for index in virtual_machine:
#         a = index.replace('\nNmap scan report for bahram-virtual-machine (', '')
#         b = a.replace(')', '')
#         virtual_machine_ip_address.append(b)
#
#     machine_ip_address = []
#     for index in machine:
#         a = index.replace('\nNmap scan report for ', '')
#         machine_ip_address.append(a)
#     return render(request, 'core/scan_network.html', {'machine': machine_ip_address})


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
