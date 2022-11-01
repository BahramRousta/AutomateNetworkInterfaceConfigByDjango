from rest_framework import serializers


class DeviceSerializers(serializers.Serializer):
    device_ip_address = serializers.CharField(max_length=50)


class RouterSerializer(serializers.Serializer):
    router_ip = serializers.CharField()


class HostSerializer(serializers.Serializer):
    current_ip = serializers.IPAddressField(required=True)


class DeviceNetworkSerializer(HostSerializer):
    new_ip = serializers.IPAddressField()
    dns = serializers.ListField(max_length=25)


class ChangeIPSerializer(serializers.Serializer):
    current_ip = serializers.IPAddressField()
    new_ip = serializers.IPAddressField()


class DNSSerializer(HostSerializer):
    dns = serializers.ListField(max_length=25)


class PortSerializer(serializers.Serializer):
    host = serializers.IPAddressField()
    port = serializers.IntegerField()


class SSHKeySerializer(serializers.Serializer):
    host = serializers.IPAddressField(required=True)
    username = serializers.CharField()
    password = serializers.CharField()