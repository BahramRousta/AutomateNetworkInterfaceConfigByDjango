import time
import os.path
import yaml
from paramiko import SSHClient, AutoAddPolicy
from paramiko.rsakey import RSAKey
from paramiko.ssh_exception import AuthenticationException, SSHException

REMOTE_NETWORK_INTERFACE_PATH = '/etc/netplan/01-network-manager-all.yaml'
SSH_PATH = '/root/.ssh/id_rsa.pub'
LOCAL_PATH = 'core/localpath/01-network-manager-all.yaml'


class SSHConnect:
    def __init__(self, hostname: str, username: str):
        self.sftp_client = None
        self.ssh_client = None
        self.hostname = hostname
        self.username = username

    def open_session(self):
        """
        Open SSHConnection on remote device
        :return: ssh remote object
        """
        self.ssh_client = SSHClient()
        self.ssh_client.load_system_host_keys()
        self.ssh_client.set_missing_host_key_policy(AutoAddPolicy())
        k = RSAKey.from_private_key_file("C:\\Users\\BahramRousta\\.ssh\\id_rsa")

        try:
            self.ssh_client.connect(hostname=self.hostname,
                                    username=self.username,
                                    pkey=k)
            print('Successfully connected!')
        except AuthenticationException as err:
            raise err
        except SSHException as sshException:
            raise sshException
        else:
            return self.ssh_client

    def close_session(self):
        """
        close ssh connection on remote device
        :return: None
        """
        return self.ssh_client.close()

    def open_sftp_session(self):
        """
        Open a sftp session on remote device
        :return: None
        """
        self.sftp_client = self.ssh_client.open_sftp()
        return self.sftp_client

    def close_sftp_session(self):
        return self.sftp_client.close()

    def get_file(self, localpath):
        return self.sftp_client.get(remotepath=REMOTE_NETWORK_INTERFACE_PATH, localpath=localpath)

    def put_file(self, localpath):
        return self.sftp_client.put(localpath=localpath, remotepath=REMOTE_NETWORK_INTERFACE_PATH)

    def modify_config(self, new_ip_address=None, dns=None, get_way=None, localpath=None, ethernets=None):

        with open(localpath, 'r') as reader:
            data = yaml.safe_load(reader)

            for key,  value in list(data['network']['ethernets'].items()):
                print(ethernets)
                print(key)
                if ethernets != key:
                    data['network']['ethernets'][f'{ethernets}'] = data['network']['ethernets'].pop(str(key))

                if new_ip_address:
                    print(new_ip_address)
                    # Modify IP address
                    data['network']['ethernets'][f'{ethernets}']['addresses'] = [new_ip_address]

                if dns:
                    # Modify DNS
                    data['network']['ethernets'][ethernets]['nameservers']['addresses'] = dns

                if get_way:
                    # Modify Get_way
                    data['network']['ethernets'][ethernets]['gateway4'] = get_way

        with open(localpath, 'w') as writer:
            new_config_file = yaml.dump(data, writer)
        return new_config_file

    def apply_config(self, delay):
        remote_device = self.ssh_client.invoke_shell()
        remote_device.send(f'netplan apply\n')
        time.sleep(delay)
        out = remote_device.recv(65000)
        print(out.decode())
        print('Configuration successful')
        self.close_session()
        return out

def _handle_config(hostname, username, new_ip=None, dns=None, get_way=None, ethernets=None):
    device = SSHConnect(hostname=hostname,
                        username=username)
    device.open_session()

    device.open_sftp_session()

    if new_ip:
        device.modify_config(new_ip_address=f'{new_ip}/24', ethernets=ethernets,
                             localpath='core/localpath/01-network-manager-all.yaml')
    device.modify_config(dns=dns, get_way=get_way, ethernets=ethernets, new_ip_address=f'{new_ip}/24',
                             localpath='core/localpath/01-network-manager-all.yaml')

    device.put_file(localpath='core/localpath/01-network-manager-all.yaml')

    device.close_sftp_session()
    device.apply_config(delay=3)
    device.close_session()
    return None