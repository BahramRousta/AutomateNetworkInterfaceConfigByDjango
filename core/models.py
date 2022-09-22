from django.db import models


class DeviceIpAddress(models.Model):
    ip = models.GenericIPAddressField()

    def __str__(self):
        return self.ip
