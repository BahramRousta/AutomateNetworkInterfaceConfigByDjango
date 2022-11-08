from rest_framework import serializers


class DeviceSerializers(serializers.Serializer):
    ip_address = serializers.ListField()


class RouterSerializer(serializers.Serializer):
    router_ip = serializers.CharField()


class HostSerializer(serializers.Serializer):
    current_ip = serializers.IPAddressField(required=False)
    new_ip = serializers.IPAddressField(required=False)
    dns = serializers.ListField(required=False)
    get_way = serializers.IPAddressField(required=False)


class DeviceNetworkSerializer(serializers.Serializer):
    devices = serializers.ListField(child=HostSerializer())


class PortSerializer(serializers.Serializer):
    host = serializers.IPAddressField()
    port = serializers.IntegerField()


class SSHKeySerializer(serializers.Serializer):
    host = serializers.IPAddressField(required=True)
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True)
