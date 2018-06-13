# -*- coding: utf-8 -*-

import socket
import platform
import threading
import time
import sys

from etc import constants
from struct import *

mutex=threading.Lock()

class PortScanner:
    # default ports to be scanned is top 1000
    __port_list_top_1000 = constants.port_list_top_1000
    __port_list_top_100 = constants.port_list_top_100
    __port_list_top_50 = constants.port_list_top_50

    # default thread number limit
    __thread_limit = 1000

    # default connection timeout time in seconds
    __delay = 10

    port_index=0


    @classmethod
    def __usage(cls):
        """
        Return the usage information for invalid input host name.
        """
        print('python Port Scanner v0.1')
        print('please make sure the input host name is in the form of "something.com" or "http://something.com!"\n')

    def __init__(self, target_ports=None):
        """
        Constructor of a PortScanner object. If target_ports is a list, this list of ports will be used as
        the port list to be scanned. If the target_ports is a int, it should be 50, 100 or 1000, indicating
        which default list will be used.

        :param target_ports: if this args is a list, then this list of ports that is going to be scanned,
        default to self.__port_list_top_1000. if this args is an int, then it should be 50, 100 or 1000. And
        the corresponding default list will be used respectively.
        :type target_ports: list or int
        """
        if target_ports is None:
            self.target_ports = self.__port_list_top_1000
        elif type(target_ports) == list:
            self.target_ports = target_ports
        elif type(target_ports) == int:
            self.target_ports = self.check_default_list(target_ports)

    def check_default_list(self, target_port_rank):
        """
        Check the input target port rank. The target port rank should be 50, 100 or 1000.
        And for a valid input, corresponding port list will be returned.

        :param target_port_rank: top K commonly used port list to be returned.
        :return: top K commonly used port list.
        """
        if (
            target_port_rank != 50 and
            target_port_rank != 100 and
            target_port_rank != 1000
        ):
            raise ValueError(
                'Invalid port rank {}. Should be 50, 100 or 1,000.'.format(target_port_rank)
            )

        if target_port_rank == 50:
            return self.__port_list_top_50
        elif target_port_rank == 100:
            return self.__port_list_top_100
        else:
            return self.__port_list_top_1000

    def scan(self, host_name, message=''):
        """
        This is the function need to be called to perform port scanning

        :param host_name: the hostname that is going to be scanned
        :param message: the message that is going to be included in the scanning packets
        in order to prevent ethical problem (default: '').
        :return: a dict object containing the scan results for a given host in the form of
        {port_number: status}
        :rtype: dict
        """
        host_name = str(host_name)
        if 'http://' in host_name or 'https://' in host_name:
            host_name = host_name[host_name.find('://') + 3:]

        print('*' * 60 + '\n')
        print('start scanning website: {}'.format(host_name))

        try:
            server_ip = socket.gethostbyname(host_name)
            print('server ip is: {}'.format(str(server_ip)))

        except socket.error:
            # If the DNS resolution of a website cannot be finished, abort that website.
            print('hostname {} unknown!!!'.format(host_name))
            self.__usage()
            return {}
            # May need to return specific value to indicate the failure.
        
        source_ip='192.168.121.128'
        dest_ip=server_ip
        

        start_time = time.time()

        thread = threading.Thread(target=self.syn_recv, args=(source_ip, dest_ip))
        thread.start()

        for port in self.target_ports:
            self.syn_send(source_ip, dest_ip,port)
                    
        # Wait until all ports being scanned
        while self.port_index < len(self.target_ports):
            time.sleep(0.01)
            continue
        stop_time = time.time()

        print('host {} scanned in  {} seconds'.format(host_name, stop_time - start_time))
        print('finished scan!\n')

        return

    def set_thread_limit(self, limit):
        """
        Set the maximum number of thread for port scanning

        :param limit: the maximum number of thread running concurrently, default to 1000.
        """
        limit = int(limit)

        if limit <= 0 or limit > 50000:
            print(
                'Warning: Invalid thread number limit {}!'
                'Please make sure the thread limit is within the range of (1, 50,000)!'.format(limit)
            )
            print('The scanning process will use default thread limit 1,000.')
            return

        self.__thread_limit = limit

    def set_delay(self, delay):
        """
        Set the time out delay for port scanning in seconds

        :param delay: the time in seconds that a TCP socket waits until timeout, default to 10s.
        """
       
            

        self.__delay = delay

    def show_target_ports(self):
        """
        Print out and return the list of ports being scanned.

        :return: list of ports scanned by current Scanner object.
        :rtype: list
        """
        print ('Current port list is:')
        print (self.target_ports)
        return self.target_ports

    def show_delay(self):
        """
        Print out and return the delay in seconds that a TCP socket waits until timeout.

        :return: timeout interval of the TCP connection in seconds.
        :rtype: int
        """
        print ('Current timeout delay is {} seconds.'.format(self.__delay))
        return self.__delay

    def show_top_k_ports(self, k):
        """
        Print out and return top K commonly used ports. K should be 50, 100 or 1000.

        :param k: top K list will be returned.
        :type k: int
        :return: top K commonly used ports.
        :rtype: list
        """
        port_list = self.check_default_list(k)
        print('Top {} commonly used ports:'.format(k))
        print(port_list)
        return port_list


    # 计算校验和
    def checksum(self, data):
        s = 0
        n = len(data) % 2
        for i in range(0, len(data)-n, 2):
            s+= ((ord(data[i])<<8) + ord(data[i+1]))
        if n:
            s+= ord(data[i+1])
        while (s >> 16):
            s = (s & 0xFFFF) + (s >> 16)
        s = ~s & 0xffff
        return s
    
    def CreateSocket(self, source_ip,dest_ip):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        except socket.error, msg:
            print 'Socket create error: ',str(msg[0]),'message: ',msg[1]
            sys.exit()
    
       # 设置手工提供IP头部
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        return s
    
    # 创建IP头部
    def CreateIpHeader(self, source_ip, dest_ip):
        packet = ''

        # ip 头部选项
        headerlen = 5
        version = 4
        tos = 0
        tot_len = 20 
        id = 0
        frag_off = 0    
        ttl = 255
        protocol = socket.IPPROTO_TCP
        check = 0
        saddr = socket.inet_aton ( source_ip )
        daddr = socket.inet_aton ( dest_ip )
        hl_version = (version << 4) + headerlen
        ip_header = pack('!BBHHHBBH4s4s', hl_version, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr)

        return ip_header

# 创建TCP头部
    def create_tcp_syn_header(self, source_ip, dest_ip, dest_port):
        # tcp 头部选项
        source = 1234  # 随机化一个源端口
        seq = 0
        ack_seq = 0
        doff = 5
        reserved=0
        # tcp flags
        fin = 0
        syn = 1
        rst = 0
        psh = 0
        ack = 0
        urg = 0
        window = socket.htons (5840)    # 最大窗口大小
        check = 0
        urg_ptr = 0
        offset_res = (doff << 4) + reserved
        tcp_flags = fin + (syn<<1) + (rst<<2) + (psh<<3) + (ack<<4) + (urg<<5)
        tcp_header = pack('!HHLLBBHHH', source, dest_port, seq, ack_seq, offset_res, tcp_flags, window, check, urg_ptr)
        # 伪头部选项
        source_address = socket.inet_aton( source_ip )
        dest_address = socket.inet_aton( dest_ip )
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header)
        psh = pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, tcp_length)
        psh = psh + tcp_header
        tcp_checksum = self.checksum(psh)

        # 重新打包TCP头部，并填充正确地校验和
        tcp_header = pack('!HHLLBBHHH', source, dest_port, seq, ack_seq, offset_res, tcp_flags, window, tcp_checksum, urg_ptr)
        return tcp_header

    def create_tcp_rst_header(self, source_ip, dest_ip, dest_port):
        # tcp 头部选项
        source = 1234  # 随机化一个源端口
        seq = 0
        ack_seq = 0
        doff = 5
        reserved=0
        # tcp flags
        fin = 0
        syn = 0
        rst = 1
        psh = 0
        ack = 0
        urg = 0
        window = socket.htons (5840)    # 最大窗口大小
        check = 0
        urg_ptr = 0
        offset_res = (doff << 4) + reserved
        tcp_flags = fin + (syn<<1) + (rst<<2) + (psh<<3) + (ack<<4) + (urg<<5)
        tcp_header = pack('!HHLLBBHHH', source, dest_port, seq, ack_seq, offset_res, tcp_flags, window, check, urg_ptr)
        # 伪头部选项
        source_address = socket.inet_aton( source_ip )
        dest_address = socket.inet_aton( dest_ip )
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header)
        psh = pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, tcp_length)
        psh = psh + tcp_header
        tcp_checksum = self.checksum(psh)

        # 重新打包TCP头部，并填充正确地校验和
        tcp_header = pack('!HHLLBBHHH', source, dest_port, seq, ack_seq, offset_res, tcp_flags, window, tcp_checksum, urg_ptr)
        return tcp_header


    def syn_send(self, source_ip, dest_ip,port) :
        p=port
        s = self.CreateSocket(source_ip, dest_ip)
        ip_header = self.CreateIpHeader(source_ip, dest_ip)
        tcp_header = self.create_tcp_syn_header(source_ip, dest_ip,p)
        packet_syn = ip_header + tcp_header

        s.sendto(packet_syn, (dest_ip, p))
        

    def syn_recv(self,source_ip, dest_ip):

        recv_socket=self.CreateSocket(source_ip, dest_ip)

        while self.port_index < len(self.target_ports):
                data=recv_socket.recvfrom(1024) [0][0:]

                port=(ord(data[20])<<8)+ord(data[21])
                print "get packet from: "+str(port)

                if port in self.target_ports:
                    self.port_index=self.port_index+1
                    print "port_index:"+str(self.port_index)
                    if ord(data[33]) == 0x12:
                        print "port "+str(port)+" open"
                        ip_header = self.CreateIpHeader(source_ip, dest_ip)
                        tcp_rst_header=self.create_tcp_rst_header(source_ip, dest_ip,port)
                        packet_rst= ip_header + tcp_rst_header
                        recv_socket.sendto(packet_rst, (dest_ip, port))
                        print "rst sended"
                        print
                    else :
                        print "port "+str(port)+" close"
                        print
                else:
                    continue
        return 

