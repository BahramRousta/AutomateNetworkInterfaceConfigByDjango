import time
import nmap
import paramiko
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .utils import SSHConnect, _handle_config
from .serializers import (
    DeviceSerializers,
    RouterSerializer,
    DeviceNetworkSerializer,
    HostSerializer,
    PortSerializer,
    SSHKeySerializer,
)
from .models import ConnectDevice, Port, Host


class AddSSHKey(APIView):

    def post(self, request):
        serializer = SSHKeySerializer(data=request.data)
        if serializer.is_valid():
            host = serializer.validated_data['host']
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']

            session = paramiko.SSHClient()

            session.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            # session.load_system_host_keys()

            session.connect(hostname=host,
                            username=username,
                            password=password)

            sftp = session.open_sftp()
            sftp.put(localpath='C:\\Users\BahramRousta\\.ssh\\id_rsa.pub',
                     remotepath=f'/{username}/.ssh/authorized_keys')
            sftp.close()
            session.close()
            return Response(status=status.HTTP_200_OK, data={'Message': 'Config done.'})
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST)


class ScanNetwork(APIView):
    """
    Scan devices up in network.
    @return: device ip address, hostname, status, mac address and device vendor.
    """

    def post(self, request):
        serializer = RouterSerializer(data=request.data)
        if serializer.is_valid():

            """
                Sample for check all devices up in local network: 192.168.1.*
            """

            router_ip = serializer.validated_data['router_ip']

            nm = nmap.PortScanner()
            nm.scan(arguments=f"-sn {router_ip}")
            ip_address = nm.all_hosts()

            hosts_name = []
            host_name = [(x, nm[x]['hostnames'][0]['name']) for x in nm.all_hosts()]
            for hostname in host_name:
                hosts_name.append(hostname[1])

            hosts_status = []
            host_status = [(y, nm[y]['status']["state"]) for y in nm.all_hosts()]
            for y in host_status:
                hosts_status.append(y[1])

            mac_address = []
            mac_addresses = [(z, nm[z]['addresses']) for z in nm.all_hosts()]
            for i in mac_addresses:
                if "mac" in i[1]:
                    mac_address.append(i[1]['mac'])
                else:
                    mac_address.append("No mac detected")

            vendors = []
            vendor = [(z, nm[z]['vendor']) for z in nm.all_hosts()]
            for i in vendor:
                vendors.append(list(i[1].values()))

            devices_log = list(zip(ip_address, hosts_name, hosts_status, mac_address, vendors))

            for device in devices_log:
                try:
                    mch = ConnectDevice.objects.filter(ip_address=device[0]).first()

                    if mch is None:
                        new_device = ConnectDevice.objects.create(ip_address=device[0],
                                                                  host_name=device[1],
                                                                  status=device[2],
                                                                  mac_address=device[3],
                                                                  vendor=device[4]
                                                                  )
                except:
                    pass
            return Response(status=status.HTTP_200_OK, data=devices_log)
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST)


class PingDevice(APIView):
    """
    Ping a device.
    @return: device status.
    """

    def get(self, request):

        serializer = DeviceSerializers(data=request.query_params)
        if serializer.is_valid():
            ip_address = serializer.validated_data['ip_address']

            opt_put = []
            for ip in ip_address:
                data = {}
                nm = nmap.PortScanner()

                nm.scan(hosts=f'{ip}', arguments='-n -sP')

                hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]

                for host, device_status in hosts_list:
                    if device_status == "Down" or "":
                        return Response(status=status.HTTP_400_BAD_REQUEST, data={'status': 'Host is down'})
                    else:
                        data[f'{ip} status'] = f"{host} is {device_status}"
                        opt_put.append(data[f'{ip} status'])
            return Response(status=status.HTTP_200_OK, data=opt_put)
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST, data=serializer.errors)


class GetOSDevice(APIView):
    """
    Detect device OS.
    """

    def post(self, request):
        serializer = DeviceSerializers(data=request.data)
        if serializer.is_valid():
            ip_address = serializer.validated_data['ip_address']

            oup_put = []
            for ip in ip_address:
                item = {}
                try:
                    device = Host.objects.filter(ip_address=ip).first()
                    if device is None:
                        return Response(status=status.HTTP_408_REQUEST_TIMEOUT, data="Host is not valid.")
                    else:
                        nm = nmap.PortScanner()
                        nm.scan(f"{ip}", arguments="--privileged -O")
                        for h in nm.all_hosts():
                            # get computer os
                            if nm[h]['osmatch']:
                                item[f'{ip}'] = nm[h]['osmatch'][0]["name"]
                                oup_put.append(item)
                                device.os = item[f'{ip}']
                                device.save()
                except:
                    return Response(status=status.HTTP_400_BAD_REQUEST, data={'Error': 'Os detect failed.'})
            return Response(status=status.HTTP_200_OK, data=oup_put)
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST, data=serializer.errors)


def _get_device(host):
    try:
        device = Host.objects.get(ip_address=host)
        return device
    except:
        return Response(status=status.HTTP_400_BAD_REQUEST, data={"Message": "Host is not valid."})


class FindDeviceNetworkConnection(APIView):

    def post(self, request):
        serializer = DeviceNetworkSerializer(data=request.data)
        if serializer.is_valid():
            devices = serializer.validated_data['devices']

            for device in devices:
                current_ip = device['current_ip']

                try:
                    host = _get_device(host=current_ip)

                    connect = SSHConnect(hostname=str(host),
                                         username=host.username)
                    session = connect.open_session()
                    remote = session.invoke_shell()
                    remote.send('netstat -i\n')
                    time.sleep(2)
                    out_put = remote.recv(65000).decode()
                    split_out_put = out_put.split()

                    network_card = []
                    for string in split_out_put:

                        # In ubuntu 22.04 network card name  in wireless mode start with 'wlp'
                        if "wlp" in string:
                            network_card.append(string)
                            host.network_card_name = string
                            host.save()

                        # In ubuntu 22.04 network card name in wireless mode start with 'ens'
                        elif "ens" in string:
                            network_card.append(string)
                            host.network_card_name = string
                            host.save()
                    return Response(status=status.HTTP_200_OK, data=network_card)
                except:
                    return Response(status=status.HTTP_400_BAD_REQUEST,
                                    data={'Message': 'The operation was unsuccessful'})
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST, data=serializer.errors)


class ChangeDeviceNetworkInterFace(APIView):
    """
    Change linux(Ubuntu 22.04) device ip address through ssh and sftp connection.
    """
    def post(self, request):
        serializer = DeviceNetworkSerializer(data=request.data)
        if serializer.is_valid():
            devices = serializer.validated_data['devices']

            for device in devices:
                current_ip = device['current_ip']
                new_ip = device['new_ip']
                dns = device['dns']
                get_way = device['get_way']

                try:
                    host = Host.objects.filter(ip_address=current_ip).first()

                    if host is None:
                        return Response(status=status.HTTP_400_BAD_REQUEST, data={'Error': 'Host ip is not valid.'})
                    else:
                        _handle_config(hostname=current_ip,
                                       username=host.username,
                                       new_ip=new_ip,
                                       dns=dns,
                                       ethernets=host.network_card_name,
                                       get_way=get_way)
                    host.ip_address = new_ip
                    host.save()
                    return Response(status=status.HTTP_200_OK, data={'status': 'Configuration done.'})
                except:
                    return Response(status=status.HTTP_400_BAD_REQUEST, data={'Error': 'Configuration failed.'})
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST, data=serializer.errors)


class ChangeDeviceIp(APIView):
    """
    change device ip address.
    """

    def post(self, request):
        serializer = DeviceNetworkSerializer(data=request.data)
        if serializer.is_valid():
            devices = serializer.validated_data['devices']

            for device in devices:
                current_ip = device['current_ip']
                new_ip = device['new_ip']

                try:
                    host = Host.objects.filter(ip_address=current_ip).first()

                    if host is None:
                        return Response(status=status.HTTP_400_BAD_REQUEST, data={'Error': 'Host ip is not valid.'})
                    else:
                        _handle_config(hostname=current_ip,
                                       username=host.username,
                                       new_ip=new_ip,
                                       ethernets=host.network_card_name)
                    host.ip_address = new_ip
                    host.save()
                    return Response(status=status.HTTP_200_OK, data={'status': 'Configuration done.'})
                except:
                    return Response(status=status.HTTP_400_BAD_REQUEST, data={'Error': 'Configuration failed.'})
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST, data=serializer.errors)


class ChangeDNS(APIView):
    """
    change device dns address.
    """

    def post(self, request):
        serializer = DeviceNetworkSerializer(data=request.data)
        if serializer.is_valid():
            devices = serializer.validated_data['devices']

            for device in devices:
                current_ip = device['current_ip']
                dns = device['dns']

                try:
                    dvc = _get_device(host=current_ip)
                    _handle_config(hostname=current_ip,
                                   username=dvc.username,
                                   dns=dns,
                                   ethernets=dvc.network_card_name)
                    dvc.dns = dns
                    dvc.save()
                    return Response(status=status.HTTP_200_OK, data={'Message': 'DNS changed successfully.'})
                except:
                    return Response(status=status.HTTP_400_BAD_REQUEST, data={'Error': 'Configuration failed.'})
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST, data=serializer.errors)


class CheckPort(APIView):

    def _change_port_status(self, request):
        serializer = PortSerializer(data=request.data)
        if serializer.is_valid():
            host = serializer.validated_data['host']
            port = serializer.validated_data['port']

            try:
                dvc = _get_device(host)
                connect = SSHConnect(hostname=str(dvc),
                                     username=dvc.username)
                session = connect.open_session()
                remote = session.invoke_shell()

                # post method open port on server
                if request.method == "POST":
                    remote.send(f'sudo ufw allow {port}\n')

                # patch method close port on server
                if request.method == "PATCH":
                    remote.send(f'sudo ufw deny {port}\n')

                time.sleep(2)
                out = remote.recv(65000)
                print(out.decode())
                print('Configuration successful')
                remote.close()
                return Response(status=status.HTTP_200_OK, data={'Message': 'Configuration done.'})
            except:
                return Response(status=status.HTTP_400_BAD_REQUEST, data={'Error': 'Configuration failed.'})
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST, data=serializer.errors)

    def get(self, request):
        serializer = DeviceSerializers(data=request.query_params)
        if serializer.is_valid():
            hosts = serializer.validated_data['ip_address']
            try:
                response = {}
                for host in hosts:
                    device = _get_device(host=host)
                    nm = nmap.PortScanner()
                    nm.scan(arguments=str(device))

                    # Get host name and open port list
                    host_name = [(x, nm[x]['tcp']) for x in nm.all_hosts()]

                    # Get port, state and name from host_name
                    all_port_info = []
                    for port in host_name[1][1]:
                        # Save status and name of port
                        port_info = {}
                        # Save port_info
                        save_port = {}

                        port_info['staus'] = host_name[1][1][port]['state']
                        port_info['name'] = host_name[1][1][port]['name']
                        save_port[f'{port}'] = port_info
                        all_port_info.append(save_port)

                        try:
                            # Checking that the port exists in the ports table
                            check_port = Port.objects.filter(number=port).first()
                            if check_port.host.id == device.id:
                                # Update check_port status
                                check_port.name = host_name[1][1][port]['name']
                                check_port.state = host_name[1][1][port]['state']
                                check_port.save()
                        except:
                            Port.objects.create(host_id=device.id,
                                                number=port,
                                                name=host_name[1][1][port]['name'],
                                                state=host_name[1][1][port]['state'])
                    response[f'{host}'] = all_port_info
                return Response(status=status.HTTP_200_OK, data=response)
            except:
                return Response(status=status.HTTP_400_BAD_REQUEST, data={"Error": "Scan failed"})
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST, data=serializer.errors)

    def post(self, request):
        """
        Open port on server by using ufw
        """
        return self._change_port_status(request=request)

    def patch(self, request):
        """
        Close port on server by using ufw
        """
        return self._change_port_status(request=request)


class FireWall(APIView):

    def _change_firewall_status(self, request):

        if request.method == "GET":
            serializer = DeviceSerializers(data=request.query_params)
        else:
            serializer = DeviceSerializers(data=request.data)

        if serializer.is_valid():
            ip_address = serializer.validated_data['ip_address']

            try:
                device = Host.objects.filter(ip_address=ip_address[0]).first()
                if device is None:
                    return Response(status=status.HTTP_400_BAD_REQUEST, data={"Error": "Host ip is not valid."})
                else:
                    connect = SSHConnect(hostname=ip_address[0],
                                         username=device.username)
                    session = connect.open_session()
                    remote = session.invoke_shell()

                    if request.method == "GET":
                        remote.send(f'ufw status\n')
                        time.sleep(2)
                        out = remote.recv(65000)
                        check = out.decode().split()
                        remote.close()
                        if 'active' in check:
                            return Response(status=status.HTTP_200_OK, data={'Message': 'Firewall is active.'})
                        else:
                            return Response(status=status.HTTP_200_OK, data={'Message': 'Firewall is disable.'})

                    if request.method == "POST":
                        commands = [f'ufw enable\n', 'y\n']
                        for command in commands:
                            remote.send(command)

                    if request.method == "PATCH":
                        remote.send(f'ufw disable\n')

                    time.sleep(2)
                    out = remote.recv(65000)
                    print(out.decode())
                    print('Configuration successful')
                    remote.close()
                    return Response(status=status.HTTP_200_OK, data={'Message': 'Configuration done.'})
            except:
                return Response(status=status.HTTP_400_BAD_REQUEST, data={'Error': 'Configuration failed.'})
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST, data=serializer.errors)

    def get(self, request):
        """
        Get ufw firewall status
        :param request:
        :return:
        """
        return self._change_firewall_status(request=request)

    def post(self, request):
        """
        Enable ufw firewall
        :param request:
        :return:
        """
        return self._change_firewall_status(request=request)

    def patch(self, request):
        """
        Disable ufw firewall
        :param request:
        :return:
        """
        return self._change_firewall_status(request=request)
