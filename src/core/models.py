from django.db import models


class Devices(models.Model):
    ip_address = models.GenericIPAddressField()
    host_name = models.CharField(max_length=50)
    status = models.CharField(max_length=4)
    mac_address = models.CharField(max_length=20,
                                   null=True,
                                   blank=True)
    vendor = models.CharField(max_length=100)
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return "{} - {}".format(self.ip_address, self.host_name)
