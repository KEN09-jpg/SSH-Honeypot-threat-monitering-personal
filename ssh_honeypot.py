#libraries
import logging
from logging.handlers import RotatingFileHandler
import socket
import paramiko
import threading
#Constants
logging_format = logging.Formatter('%(message)s') #how do we want our messages formatted on the file
SSH_BANNER = "SSH-2.0-MySSHServer_1.0"
#host_key = 'server.key'
host_key = paramiko.RSAKey(filename='server.key')

#Loggers & Logging Files
funnel_logger = logging.getLogger('FunnelLogger') #Name will capture ip addresses n stuff
funnel_logger.setLevel(logging.INFO) #use the log module for info level
funnel_handler = RotatingFileHandler('audits.log',maxBytes=2000, backupCount=5) #set where going to log 
funnel_handler.setFormatter(logging_format) # setting the format 
funnel_logger.addHandler(funnel_handler) # add it to funnel object//giving the 2 above handler

creds_logger = logging.getLogger('CredsLogger') 
creds_logger.setLevel(logging.INFO) 
creds_handler = RotatingFileHandler('cmd_audits.log',maxBytes=2000, backupCount=5) 
creds_handler.setFormatter(logging_format)  
creds_logger.addHandler(creds_handler)

#Emulates SHell

def emulated_shell(channel, client_ip):
    channel.send(b'corporate-jumpbox2$ ')
    command = b"" #listening to user input
    while True:
        char = channel.recv(1)
        channel.send(char)
        if not char:
            channel.close()

        command += char

        if char == b'\r':
            if command.strip() == b'exit':
                response = b'\n Goodbye!\n'
                channel.close()
            elif command.strip() == b'pwd':
                response = b"\n" + b'\\usr\\local'+ b'\r\n'  
                creds_logger.info(f'Command {command.strip()}' + 'executed by ' + f'{client_ip}')      
            elif command.strip() == b'whoami':
                response = b"\n" + b"corpuser1" + b"\r\n"
                creds_logger.info(f'Command {command.strip()}' + 'executed by ' + f'{client_ip}') 
            elif command.strip() == b'ls':
                response = b'\n' + b"jumpbox1.conf" + b"\r\n"
                creds_logger.info(f'Command {command.strip()}' + 'executed by ' + f'{client_ip}') 
            elif command.strip() == b'cat jump1.conf':
                 response = b'\n' + b"Go to deebooda.com." + b"\r\n"
                 creds_logger.info(f'Command {command.strip()}' + 'executed by ' + f'{client_ip}') 
            else:
                response = b"\n" + bytes(command.strip()) + b"\r\n"   
                creds_logger.info(f'Command {command.strip()}' + 'executed by ' + f'{client_ip}')  
            channel.send(response)
            channel.send(b'corporate-jumpbox2$ ')
            command = b""


#SSH Server + Sockets

class Server(paramiko.ServerInterface):
    def __init__(self, client_ip, input_username=None, Input_password=None):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = Input_password

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED    

    def get_allowed_auths(self, username):
        return "password"
    
    def check_auth_password(self, username, password):
        funnel_logger.info(f'Client {self.client_ip} attempted connection with ' + f'username:{username}, '+ f'password: {password}')
        creds_logger.info(f'{self.client_ip}, {username}, {password}')
        if self.input_username is not None and self.input_password is not None:
            if username == self.input_username and password == self.input_password:
                return paramiko.AUTH_SUCCESSFUL
            else:
                return paramiko.AUTH_FAILED
        else:
            return paramiko.AUTH_SUCCESSFUL
        
    def check_channel_shell_request(self, channel):
        self.event.set()
        return True 
    
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True 
    
    def check_channel_exec_request(self, channel, command):
        command = str(command)
        return True

def client_handle(client, addr, username, password):
    client_ip = addr[0]
    print(f"{client_ip} has connected to the server.")
 
    try:

        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER
        server = Server(client_ip=client_ip, input_username=username, Input_password=password)

        transport.add_server_key(host_key)

        transport.start_server(server=server)

        channel = transport.accept(100)
        
        if channel is None:
            print("no channel is open.")
            return

        standard_banner = "Hit the Ground running!\r\n\r\n"

        channel.send(standard_banner)

        emulated_shell(channel, client_ip=client_ip)    
    except Exception as error:
        print(error)
        print("!!! Error !!!")
    finally:
        try:
            transport.close()
        except Exception as error:
            print(error)
            print("!! Error !!")
        client.close()            

#Provision SSH-based Honeypots

def honeypot(address, port, username, password):

    socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socks.bind((address, port))

    socks.listen(100)
    print(f"SSH server is listening on port {port}.")

    while True:
        try:
            client, addr = socks.accept()
            ssh_honeypot_thread = threading.Thread(target=client_handle, args=(client, addr, username, password))
            ssh_honeypot_thread.start()

        except Exception as error:
            print(error)

honeypot('127.0.0.1', 2223, username=None, password=None)
