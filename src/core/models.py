from django.db import models


class Host(models.Model):
    ip_address = models.GenericIPAddressField()
    dns = models.CharField(max_length=25)
    get_way = models.GenericIPAddressField()
    username = models.CharField(max_length=100)
    password = models.CharField(max_length=100)
    os = models.CharField(max_length=100,
                          null=True,
                          blank=True)
    network_card_name = models.CharField(max_length=25, null=True, blank=True)

    def __str__(self):
        return self.ip_address


class ConnectDevice(models.Model):
    """
    Save connected device when scan network
    """
    ip_address = models.GenericIPAddressField()
    host_name = models.CharField(max_length=50)
    status = models.CharField(max_length=4)
    mac_address = models.CharField(max_length=20,
                                   null=True,
                                   blank=True)
    vendor = models.CharField(max_length=100)
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    os = models.CharField(max_length=200,
                          null=True,
                          blank=True)

    def __str__(self):
        return self.ip_address


class Port(models.Model):
    host = models.ForeignKey(Host,
                             on_delete=models.CASCADE,
                             related_name="ports")
    name = models.CharField(max_length=25)
    number = models.IntegerField()
    state = models.CharField(max_length=10)
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} - {self.state}"
