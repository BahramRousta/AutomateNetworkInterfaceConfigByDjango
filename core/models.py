from django.db import models


class DeviceIpAddress(models.Model):
    ip_address = models.GenericIPAddressField()
    status = models.CharField(max_length=4)
    host_name = models.CharField(max_length=50)

    def __str__(self):
        return "{} - {}".format(self.ip_address, self.host_name)
