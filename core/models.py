from django.db import models


class MachineIpAddress(models.Model):
    ip = models.GenericIPAddressField()

    def __str__(self):
        return self.ip
