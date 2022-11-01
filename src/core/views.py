import nmap
import paramiko
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .utils import SSHConnect
from .serializers import (
    DeviceSerializers,
    RouterSerializer,
    DeviceNetworkSerializer,
    DNSSerializer,
    HostSerializer,
    PortSerializer,
    SSHKeySerializer, ChangeIPSerializer
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

            session.load_system_host_keys()

            session.connect(hostname=host,
                            username=username,
                            password=password)

            sftp = session.open_sftp()
            sftp.put(localpath='C:\\Users\BahramRousta\\.ssh\\id_rsa.pub',
                               remotepath='/home/iris/.ssh/id_rsa')
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
            device_ip_address = serializer.validated_data['device_ip_address']
            nm = nmap.PortScanner()
            nm.scan(hosts=f'{device_ip_address}', arguments='-n -sP')
            data = {}
            hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]

            for host, device_status in hosts_list:
                if device_status == "Down" or "":
                    break
                else:
                    data['status'] = f"{host} is {device_status}"
                    return Response(status=status.HTTP_200_OK, data=data)
            return Response(status=status.HTTP_400_BAD_REQUEST, data={'status': 'Host is down'})
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST, data=serializer.errors)


class GetOSDevice(APIView):
    """
    Detect device OS.
    """

    def get(self, request):
        serializer = DeviceSerializers(data=request.query_params)
        if serializer.is_valid():
            ip_address = serializer.validated_data['device_ip_address']

            try:
                device = Host.objects.filter(ip_address=ip_address).first()
                item = {}
                if device:
                    nm = nmap.PortScanner()
                    nm.scan(f"{ip_address}", arguments="--privileged -O")

                    for h in nm.all_hosts():
                        # get computer os
                        if nm[h]['osmatch']:
                            item['osmatch'] = nm[h]['osmatch'][0]["name"]
                            device.os = item['osmatch']
                            device.save()
                return Response(status=status.HTTP_200_OK, data=item)
            except:
                return Response(status=status.HTTP_400_BAD_REQUEST, data={"Error": "Host not found."})
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST)


def _handle_config(hostname, username, new_ip=None, dns=None, get_way=None):
    device = SSHConnect(hostname=hostname,
                        username=username)
    device.open_session()
    device.open_sftp_session()
    device.get_file(localpath='core/localpath/01-network-manager-all.yaml')

    if new_ip:
        device.modify_config(new_ip_address=f'{new_ip}/24',
                             localpath='core/localpath/01-network-manager-all.yaml')

    if dns:
        device.modify_config(dns=dns,
                             localpath='core/localpath/01-network-manager-all.yaml')

    if get_way:
        device.modify_config(get_way=get_way,
                             localpath='core/localpath/01-network-manager-all.yaml')

    device.put_file(localpath='core/localpath/01-network-manager-all.yaml')

    device.close_sftp_session()
    device.apply_config(delay=3)
    device.close_session()
    return None


class ChangeDeviceNetworkInterFace(APIView):
    """
    Change linux(Ubuntu) device ip address through ssh and sftp connection.
    """

    def post(self, request):
        serializer = DeviceNetworkSerializer(data=request.data)
        if serializer.is_valid():
            current_ip = serializer.validated_data['current_ip']
            new_ip = serializer.validated_data['new_ip']
            dns = serializer.validated_data['dns']

            try:
                device = Host.objects.filter(ip_address=current_ip).first()

                if device is None:
                    return Response(status=status.HTTP_400_BAD_REQUEST, data={'Error': 'Device ip is not valid.'})
                else:
                    _handle_config(hostname=current_ip,
                                   username=device.username,
                                   new_ip=new_ip,
                                   dns=dns)
                    device.ip_address = new_ip
                    device.save()
                    return Response(status=status.HTTP_200_OK, data={'status': 'Configuration is down.'})
            except:
                return Response(status=status.HTTP_400_BAD_REQUEST, data={'Error': 'Configuration failed.'})
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST, data=serializer.errors)


class ChangeDeviceIp(APIView):
    """
    change device ip address.
    """

    def post(self, request):
        serializer = ChangeIPSerializer(data=request.data)
        if serializer.is_valid():
            current_ip = serializer.validated_data['current_ip']
            new_ip = serializer.validated_data['new_ip']

            try:
                device = Host.objects.filter(ip_address=current_ip).first()

                if device is None:
                    return Response(status=status.HTTP_400_BAD_REQUEST, data={'Error': 'Device ip is not valid.'})
                else:
                    _handle_config(hostname=current_ip,
                                   username=device.username,
                                   new_ip=new_ip)
                    device.ip_address = new_ip
                    device.save()
                    return Response(status=status.HTTP_200_OK, data={'status': 'Configuration is down.'})
            except:
                return Response(status=status.HTTP_400_BAD_REQUEST, data={'Error': 'Configuration failed.'})
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST, data=serializer.errors)


class ChangeDNS(APIView):
    """
    change device dns address.
    """

    def post(self, request):
        serializer = DNSSerializer(data=request.data)
        if serializer.is_valid():
            current_ip = serializer.validated_data['current_ip']
            dns = serializer.validated_data['dns']
            try:
                device = Host.objects.filter(ip_address=current_ip).first()

                if device is None:
                    return Response(status=status.HTTP_400_BAD_REQUEST, data={'Error': 'Device ip is not valid.'})
                else:
                    _handle_config(hostname=current_ip,
                                   username=device.username,
                                   dns=dns)
                    device.dns = dns
                    device.save()
                    return Response(status=status.HTTP_200_OK, data={'status': 'Configuration is down.'})
            except:
                return Response(status=status.HTTP_400_BAD_REQUEST, data={'Error': 'Configuration failed.'})
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST, data=serializer.errors)


class ChangeGetWay(APIView):

    def post(self, request):
        serializer = RouterSerializer(data=request.data)

        if serializer.is_valid():
            current_ip = serializer.validated_data['current_ip']
            get_way = serializer.validated_data['dns']

            try:
                device = Host.objects.filter(ip_address=current_ip).first()

                if device is None:
                    return Response(status=status.HTTP_400_BAD_REQUEST, data={'Error': 'Device ip is not valid.'})
                else:
                    _handle_config(hostname=current_ip,
                                   username=device.username,
                                   get_way=get_way,)
                    device.get_way = get_way
                    device.save()
                    return Response(status=status.HTTP_200_OK, data={'status': 'Configuration is down.'})
            except:
                return Response(status=status.HTTP_400_BAD_REQUEST, data={'Error': 'Configuration failed.'})
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST, data=serializer.errors)


class CheckOpenedPort(APIView):

    def get(self, request):
        serializer = RouterSerializer(data=request.query_params)
        if serializer.is_valid():
            device_ip = serializer.validated_data['router_ip']

            try:
                device = Host.objects.filter(ip_address=device_ip).first()
                if device is not None:
                    nm = nmap.PortScanner()
                    nm.scan(arguments=device_ip)

                    # Get host name and open port list
                    host_name = [(x, nm[x]['tcp']) for x in nm.all_hosts()]

                    # Get port, state and name from host_name
                    ports = []
                    state = []
                    name = []
                    for port in host_name[1][1]:
                        ports.append(port)
                        state.append(host_name[1][1][port]['state'])
                        name.append(host_name[1][1][port]['name'])

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

                    # Create dict to response
                    devices_log = dict(zip(ports, zip(state, name)))
                    return Response(status=status.HTTP_200_OK, data=devices_log)
            except:
                return Response(status=status.HTTP_400_BAD_REQUEST, data={"error": "Host ip is not valid."})
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST, data=serializer.errors)

    def post(self, request):
        serializer = PortSerializer(data=request.data)
        if serializer.is_valid():
            host = serializer.validated_data['host']
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']
            port = serializer.validated_data['port']

            try:
                device = Host.objects.filter(ip_address=host).first()
                if device is not None:
                    device = SSHConnect(hostname=host,
                                        username=username,
                                        password=password)
                    device.open_session()
                else:
                    return Response(status=status.HTTP_400_BAD_REQUEST, data={'Error': 'Info is not valid.'})
            except:
                pass


class ClosePort(APIView):
    pass

