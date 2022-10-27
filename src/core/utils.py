import time
import yaml
from paramiko import SSHClient, AutoAddPolicy
from paramiko.ssh_exception import AuthenticationException, SSHException

REMOTE_NETWORK_INTERFACE_PATH = '/etc/netplan/01-network-manager-all.yaml'
LOCAL_PATH = 'core/localpath/01-network-manager-all.yaml'

class SSHConnect:
    def __init__(self, hostname: str, username: str, password: str):
        self.sftp_client = None
        self.ssh_client = None
        self.hostname = hostname
        self.username = username
        self.password = password

    def open_session(self):
        """
        Open SSHConnection on remote device
        :return: ssh remote object
        """

        self.ssh_client = SSHClient()
        self.ssh_client.set_missing_host_key_policy(AutoAddPolicy())

        try:
            self.ssh_client.connect(hostname=self.hostname,
                                    username=self.username,
                                    password=self.password)
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

    def modify_config(self, new_ip_address=None, dns=None, localpath=None):

        with open(localpath, 'r') as reader:
            data = yaml.safe_load(reader)

            # Modify IP address
            if new_ip_address:
                data['network']['ethernets']['wlp18s0']['addresses'] = [new_ip_address]

            # Modify DNS
            if dns:
                dns1 = data['network']['ethernets']['wlp18s0']['nameservers']['addresses'] = dns

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