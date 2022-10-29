import nmap
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .utils import SSHConnect
from .serializers import (
    DeviceSerializers,
    RouterSerializer,
    DeviceNetworkSerializer,
    DNSSerializer,
    HostSerializer
)
from .models import Devices, Ports


class ScanNetwork(APIView):
    """
    Scan devices up in network.
    @return: device ip address, hostname, status, mac address and device vendor.
    """

    def post(self, request):
        serializer = RouterSerializer(data=request.data)
        data = {}
        if serializer.is_valid():

            """
                Sample for check all devices up in local network:> 192.168.1.*
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
                    mch = Devices.objects.filter(ip_address=device[0]).first()

                    if mch is None:
                        new_device = Devices.objects.create(ip_address=device[0],
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
        global output
        serializer = DeviceSerializers(data=request.query_params)
        data = {}
        if serializer.is_valid():
            ip_address = serializer.validated_data['device_ip_address']

            nm = nmap.PortScanner()
            nm.scan(f"{ip_address}", arguments="--privileged -O")

            item = {}
            for h in nm.all_hosts():

                try:
                    # get computer os
                    if nm[h]['osmatch']:
                        item['osmatch'] = nm[h]['osmatch'][0]["name"]

                        device = Devices.objects.filter(ip_address=ip_address).first()
                        device.os = item['osmatch']
                        device.save()
                except:
                    # get cellphone vendor
                    if nm[h]['vendor']:
                        item['vendor'] = list(nm[h]['vendor'].values())[0]
                        device = Devices.objects.filter(ip_address=ip_address).first()
                        device.os = item['vendor']
                        device.save()

            return Response(status=status.HTTP_200_OK, data=item)
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST)


def _handle_config(hostname, username, password, new_ip=None, dns=None, getway=None):
    device = SSHConnect(hostname=hostname,
                        username=username,
                        password=password)
    device.open_session()
    device.open_sftp_session()
    device.get_file(localpath='core/localpath/01-network-manager-all.yaml')

    if new_ip:
        device.modify_config(new_ip_address=f'{new_ip}/24',
                             localpath='core/localpath/01-network-manager-all.yaml')

    if dns:
        device.modify_config(dns=dns,
                             localpath='core/localpath/01-network-manager-all.yaml')

    if getway:
        device.modify_config(getway=getway,
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
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']
            new_ip = serializer.validated_data['new_ip']
            dns = serializer.validated_data['dns']

            try:
                device = Devices.objects.filter(ip_address=current_ip).first()

                if device is None:
                    return Response(status=status.HTTP_400_BAD_REQUEST, data={'Error': 'Device ip is not valid.'})
                else:
                    _handle_config(hostname=current_ip,
                                   username=username,
                                   password=password,
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
        serializer = DeviceNetworkSerializer(data=request.data)
        if serializer.is_valid():
            current_ip = serializer.validated_data['current_ip']
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']
            new_ip = serializer.validated_data['new_ip']

            _handle_config(hostname=current_ip,
                           username=username,
                           password=password,
                           new_ip=new_ip)

            return Response(status=status.HTTP_200_OK, data={'status': 'Changed IP successfully.'})
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST, data=serializer.errors)


class ChangeDNS(APIView):
    """
    change device ip address.
    """

    def post(self, request):
        serializer = DNSSerializer(data=request.data)
        if serializer.is_valid():
            current_ip = serializer.validated_data['current_ip']
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']
            dns = serializer.validated_data['dns']

            _handle_config(hostname=current_ip,
                           username=username,
                           password=password,
                           dns=dns)

            return Response(status=status.HTTP_200_OK, data={'status': 'Changed DNS successfully.'})
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST, data=serializer.errors)


class ChangeGetWay(APIView):

    def post(self, request):
        serializer = RouterSerializer(data=request.data)
        if serializer.is_valid():
            current_ip = serializer.validated_data['current_ip']
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']
            getway = serializer.validated_data['dns']

            _handle_config(hostname=current_ip,
                           username=username,
                           password=password,
                           getway=getway)

            return Response(status=status.HTTP_200_OK, data={'status': 'GetWay changed successfully.'})
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST, data=serializer.errors)


class CheckOpenPort(APIView):

    def post(self, request):
        serializer = RouterSerializer(data=request.data)
        if serializer.is_valid():
            device_ip = serializer.validated_data['router_ip']

            try:
                device = Devices.objects.filter(ip_address=device_ip).first()
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
                            check_port = Ports.objects.filter(number=port).first()
                            if check_port.device.id == device.id:
                                # Update check_port status
                                check_port.name = host_name[1][1][port]['name']
                                check_port.state = host_name[1][1][port]['state']
                                check_port.save()
                        except:
                            Ports.objects.create(device_id=device.id,
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
