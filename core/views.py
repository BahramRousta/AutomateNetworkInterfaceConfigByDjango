import time
from django.shortcuts import render, HttpResponse
import paramiko
import yaml
from paramiko.ssh_exception import AuthenticationException


def index(request):
    hostname = "192.168.1.85"
    return render(request, 'core/index.html', {'hostname': hostname})


def change_ip_address(request):
    if request.method == "POST":
        hostname = request.POST.get('ip_address')
        new_ip_address = request.POST.get('new_ip_address')

        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            ssh_client.connect(hostname=hostname,
                               username='root',
                               password='bahram1371')
            print('Successfully connected!')
        except AuthenticationException as err:
            print(err)

        ftp_client = ssh_client.open_sftp()
        ftp_client.get(remotepath='/etc/netplan/01-network-manager-all.yaml',
                       localpath='C:/Users/Berooz Stock/Desktop/SSHConnection/01-network-manager-all.yaml')
        with open('C:/Users/Berooz Stock/Desktop/SSHConnection/01-network-manager-all.yaml', 'r') as reader:
            data = yaml.safe_load(reader)
            data['network']['ethernets']['ens33']['addresses'] = [new_ip_address]

        with open('C:/Users/Berooz Stock/Desktop/SSHConnection/01-network-manager-all.yaml', 'w') as writer:
            yaml.dump(data, writer)

        ftp_client.put(localpath='C:/Users/Berooz Stock/Desktop/SSHConnection/01-network-manager-all.yaml',
                       remotepath='/etc/netplan/01-network-manager-all.yaml')

        ftp_client.close()

        remote_device = ssh_client.invoke_shell()
        remote_device.send(f'netplan apply\n')
        time.sleep(2)
        out = remote_device.recv(10000)
        print(out.decode())
        ssh_client.close()
        return HttpResponse('ok')