from rest_framework import serializers


class DeviceSerializers(serializers.Serializer):
    device_ip_address = serializers.CharField(max_length=50)


class RouterSerializer(serializers.Serializer):
    router_ip = serializers.CharField(max_length=50)
    username = serializers.CharField(max_length=25)
    password = serializers.CharField(max_length=25)


class AuthenticatedSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=25, required=True)
    password = serializers.CharField(max_length=25, required=True)
    current_ip = serializers.IPAddressField(required=True)


class ChangeDeviceIPSerializer(AuthenticatedSerializer):
    new_ip = serializers.IPAddressField()
    dns = serializers.ListField(max_length=25, required=False)

