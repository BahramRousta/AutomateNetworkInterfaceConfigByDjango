from rest_framework import serializers


class DeviceSerializers(serializers.Serializer):
    device_ip_address = serializers.CharField(max_length=50)


class RouterSerializer(serializers.Serializer):
    router_ip = serializers.CharField(max_length=50)


class ChangeDeviceIPSerializer(serializers.Serializer):
    current_ip = serializers.IPAddressField()
    new_ip = serializers.IPAddressField()
    username = serializers.CharField(max_length=25)
    password = serializers.CharField(max_length=25)