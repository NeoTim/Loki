#       module_eigrp.py
#       
#       Copyright 2009 Daniel Mende <dmende@ernw.de>
#

#       Redistribution and use in source and binary forms, with or without
#       modification, are permitted provided that the following conditions are
#       met:
#       
#       * Redistributions of source code must retain the above copyright
#         notice, this list of conditions and the following disclaimer.
#       * Redistributions in binary form must reproduce the above
#         copyright notice, this list of conditions and the following disclaimer
#         in the documentation and/or other materials provided with the
#         distribution.
#       * Neither the name of the  nor the names of its
#         contributors may be used to endorse or promote products derived from
#         this software without specific prior written permission.
#       
#       THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#       "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#       LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#       A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#       OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#       SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#       LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#       DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#       THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#       (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#       OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import os
import sys
import signal
import threading
import socket
import struct
import time
import cmd
import fcntl
#import md5

import pcap
import dpkt

import gobject
import gtk
import gtk.glade

EIGRP_PROTOCOL_NUMBER = 0x58
EIGRP_MULTICAST_ADDRESS = "224.0.0.10"

DEFAULT_HOLD_TIME = 5

SO_BINDTODEVICE	= 25

### HELPER_FUNKTIONS ###

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24]

def ichecksum_func(data, sum=0):
    ''' Compute the Internet Checksum of the supplied data.  The checksum is
    initialized to zero.  Place the return value in the checksum field of a
    packet.  When the packet is received, check the checksum, by passing
    in the checksum field of the packet and the data.  If the result is zero,
    then the checksum has not detected an error.
    '''
    # make 16 bit words out of every two adjacent 8 bit words in the packet
    # and add them up
    for i in xrange(0,len(data),2):
        if i + 1 >= len(data):
            sum += ord(data[i]) & 0xFF
        else:
            w = ((ord(data[i]) << 8) & 0xFF00) + (ord(data[i+1]) & 0xFF)
            sum += w

    # take only 16 bits out of the 32 bit sum and add up the carries
    while (sum >> 16) > 0:
        sum = (sum & 0xFFFF) + (sum >> 16)

    # one's complement the result
    sum = ~sum

    return sum & 0xFFFF

### EIGRP_PACKET_STRUCTURES ###

class eigrp_address:
    def __init__(self, addr, len=4):
        self.addr = socket.inet_aton(addr)
        self.len = len

    def render(self):
        return self.addr + struct.pack("!B", self.len)

class eigrp_packet:
    EIGRP_VERSION = 2
    EIGRP_OPTCODE_UPDATE = 1
    EIGRP_OPTCODE_RESERVED = 2
    EIGRP_OPTCODE_QUERY = 3
    EIGRP_OPTCODE_REPLY = 4
    EIGRP_OPTCODE_HELLO = 5
    EIGRP_FLAGS_INIT = 0x00000001
    EIGRP_FLAGS_COND_RECV = 0x00000008
        
    def __init__(self, optcode = None, flags = None, seq_num = None, ack_num = None, as_num = None, data = None):
        self.optcode = optcode
        self.checksum = 0
        self.flags = flags
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.as_num = as_num
        self.data = data

    def parse(self, data):
        payload = data[20:]
        self.optcode, self.checksum, self.flags, self.seq_num, self.ack_num, self.as_num = struct.unpack("!xBHIIII", data[:20])
        return payload

    def render(self):
        data = ""
        auth = None
        auth_pos = None
        if self.data:
            for i in self.data:
                if i.__class__ == eigrp_authentication:
                    auth = i
                    auth_pos = len(data)
                else:
                    data += i.render()
            if auth:
                #data = data[0:auth_pos] + auth.render(struct.pack("!BBHIIII", self.EIGRP_VERSION, self.optcode, self.checksum, self.flags, self.seq_num, self.ack_num, self.as_num) + data) + data[auth_pos:]
                data = data[0:auth_pos] + auth.render(struct.pack("!BBIIII", self.EIGRP_VERSION, self.optcode, self.flags, self.seq_num, self.ack_num, self.as_num)) + data[auth_pos:]
                #data = data[0:auth_pos] + auth.render(struct.pack("!BIII", self.optcode, self.as_num, self.flags, self.seq_num) ) + data[auth_pos:]
        ret = struct.pack("!BBHIIII", self.EIGRP_VERSION, self.optcode, self.checksum, self.flags, self.seq_num, self.ack_num, self.as_num)
        self.checksum = ichecksum_func(ret + data)
        return struct.pack("!BBHIIII", self.EIGRP_VERSION, self.optcode, self.checksum, self.flags, self.seq_num, self.ack_num, self.as_num) + data

class eigrp_tlv:
    EIGRP_TYPE_PARAM = 0x0001
    EIGRP_TYPE_AUTH = 0x0002
    EIGRP_TYPE_SEQENCE = 0x0003
    EIGRP_TYPE_VERSION = 0x0004
    EIGRP_TYPE_NEXT_MULTICAST_SEQ = 0x0005
    EIGRP_TYPE_INTERNAL_ROUTE = 0x0102
    EIGRP_TYPE_EXTERNAL_ROUTE = 0x0103
    
    def __init__(self, type=None):
        self.type = type
        self.len = None
        self.data = None

    def parse(self, data):
        self.type, self.len = struct.unpack("!HH", data[:4])
        self.data = data[4:self.len]
        if self.len >= len(data):
            return False
        else:
            return data[self.len:]

    def render(self, data=None):
        if data and not self.data:
            return struct.pack("!HH", self.type, len(data) + 4) + data
        if not data and self.data:
            return struct.pack("!HH", self.type, self.len) + self.data

class eigrp_param(eigrp_tlv):
    def __init__(self, k1, k2, k3, k4, k5, hold_time):
        eigrp_tlv.__init__(self, eigrp_tlv.EIGRP_TYPE_PARAM)
        self.k1 = k1
        self.k2 = k2
        self.k3 = k3
        self.k4 = k4
        self.k5 = k5
        self.hold_time = hold_time

    def render(self):
        return eigrp_tlv.render(self, struct.pack("!BBBBBxH", self.k1, self.k2, self.k3, self.k4, self.k5, self.hold_time))

class eigrp_authentication(eigrp_tlv):
    def __init__(self, key, hash="md5", key_id = 1):
        eigrp_tlv.__init__(self, eigrp_tlv.EIGRP_TYPE_AUTH)
        self.key = key
        self.hash = hash
        self.key_id = key_id

    def render(self, data):
        #if self.hash == "md5":
            #m = md5.new()
            #m.update(self.key)
            #m.update(data)
            ##m.update(self.key)
            #return eigrp_tlv.render(self, struct.pack("!4BI12B", 0x00, 0x02, 0x00, 0x10, self.key_id, 0x00, 0x00, 0x00, 0x00 ,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) + m.digest())
        #else:
            return ""

class eigrp_sequence(eigrp_tlv):
    def __init__(self, addr):
        eigrp_tlv.__init__(self, eigrp_tlv.EIGRP_TYPE_SEQENCE)
        self.addr = addr

    def render(self):
        return eigrp_tlv.render(self, addr.render())

class eigrp_next_multicast_seq(eigrp_tlv):
    def __init__(self, seq):
        eigrp_tlv.__init__(self, eigrp_tlv.EIGRP_TYPE_NEXT_MULTICAST_SEQ)
        self.seq = seq

    def render(self):
        return eigrp_tlv.render(self, struct.pack("!I", self.seq))

class eigrp_version(eigrp_tlv):
    def __init__(self, ios_ver=0xc04, eigrp_ver=0x102):
        eigrp_tlv.__init__(self, eigrp_tlv.EIGRP_TYPE_VERSION)
        self.ios_ver = ios_ver
        self.eigrp_ver = eigrp_ver

    def render(self):
        return eigrp_tlv.render(self, struct.pack("!HH", self.ios_ver, self.eigrp_ver))

class eigrp_internal_route(eigrp_tlv):
    def __init__(self, next_hop, delay, bandwidth, mtu, hop_count, reliability, load, prefix, dest):
        eigrp_tlv.__init__(self, eigrp_tlv.EIGRP_TYPE_INTERNAL_ROUTE)
        self.next_hop = socket.inet_aton(next_hop)
        self.delay = delay
        self.bandwidth = bandwidth
        self.mtu = mtu
        self.hop_count = hop_count
        self.reliability = reliability
        self.load = load
        self.prefix = prefix
        self.dest = socket.inet_aton(dest)

    def render(self):
        mtu_and_hop = (self.mtu << 8) + self.hop_count
        dest = ""
        for x in xrange(0, self.prefix / 8):
            dest += self.dest[x:x+1]
        return eigrp_tlv.render(self, self.next_hop + struct.pack("!IIIBBxxB", self.delay, self.bandwidth, mtu_and_hop, self.reliability, self.load, self.prefix) + dest)

class eigrp_external_route(eigrp_tlv):
    EIGRP_EXTERNAL_PROTO_OSPF = 6
    
    def __init__(self, next_hop, originating_router, originating_as, arbitrary_tag, external_metric, external_proto, flags, delay, bandwidth, mtu, hop_count, reliability, load, prefix, dest):
        eigrp_tlv.__init__(self, eigrp_tlv.EIGRP_TYPE_EXTERNAL_ROUTE)
        self.next_hop = socket.inet_atoi(next_hop)
        self.originating_router = socket.inet_atoi(originating_router)
        self.originating_as = originating_as
        self.arbitrary_tag = arbitrary_tag
        self.external_metric = external_metric
        self.external_proto = external_proto
        self.flags = flags
        self.delay = delay
        self.bandwidth = bandwidth
        self.mtu = mtu
        self.hop_count = hop_count
        self.reliability = reliability
        self.load = load
        self.prefix = prefix
        self.dest = socket.inet_atoi(dest)

    def render(self):
        mtu_and_hop = (self.mtu << 8) + self.hop_count
        dest = ""
        for x in xrange(0, self.prefix / 8):
            dest += self.dest[x:x+1]
        return eigrp_tlv.render(self, self.next_hop + self.originating_router + struct.pack("!IIIIxxBBIIIBBxxB", self.originating_as, self.arbitrary_tag, self.external_metric, self.external_proto, self.flags, self.delay, self.bandwidth, mtu_and_hop, self.reliability, self.load, self.prefix) + dest)

### THREAD_CLASSES ###

class eigrp_hello_thread(threading.Thread):
    def __init__(self, parent, interface, as_num, auth=None, spoof=None):
        threading.Thread.__init__(self)
        self.parent = parent
        self.interface = interface
        self.running = True
        self.sock = None
        self.as_num = as_num
        self.auth = auth
        self.spoof = spoof

    def hello(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, EIGRP_PROTOCOL_NUMBER)
        self.sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, self.interface)
        if self.spoof:
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        while self.running:
            params = eigrp_param(1, 0, 1, 0, 0, 15)
            version = eigrp_version() #(0xc02, 0x300)
            args = [params, version]
            if self.auth:
                args.insert(0, self.auth)
            msg = eigrp_packet(eigrp_packet.EIGRP_OPTCODE_HELLO, 0, 0, 0, self.as_num, args)
            data = msg.render()
            if not self.spoof:
                self.sock.sendto(data, (EIGRP_MULTICAST_ADDRESS,0))
            else:
                ip = struct.pack("!BBHHHBBH", 0x45, 0xc0, len(data) + 20, 0x0000, 0x0000, 0x02, EIGRP_PROTOCOL_NUMBER, 0x0000) + self.spoof + socket.inet_aton(EIGRP_MULTICAST_ADDRESS)
                ip = ip[:10] + struct.pack("!H", ichecksum_func(ip)) + ip[12:]
                self.sock.sendto(ip + data, (EIGRP_MULTICAST_ADDRESS,0))
            time.sleep(DEFAULT_HOLD_TIME)
        self.sock.close()

    def run(self):
        self.hello()
        self.parent.log("EIGRP: Hello thread on %s terminated" % (self.interface))
        #interface.hello_thread = None

    def quit(self):
        self.running = False
        #self.join()

class eigrp_listener(threading.Thread):
    def __init__(self, parent, interface, address, listen_for_auth=False):
        threading.Thread.__init__(self)
        self.parent = parent
        self.running = True
        self.interface = interface
        self.pcap = pcap.pcap(name=interface)
        self.pcap.setnonblock()
        self.pcap.setfilter("ip proto eigrp")
        self.address = address
        self.interface = interface
        #self.as_num = as_num
        self.listen_for_auth = listen_for_auth
        
    def listen(self):
        for ts, pkt in self.pcap:
            if self.running:
                eth = dpkt.ethernet.Ethernet(pkt)
                data = str(eth.data)
                ip = dpkt.ip.IP(data)
                if ip.dst == socket.inet_aton("224.0.0.10"):
                    if not ip.src == self.address:
                        self.disp_multicast(ip.data, ip.src)
                    if self.listen_for_auth and ip.src == self.address:
                        self.disp_auth(ip.data)
                elif ip.dst == self.address:
                    self.disp_unicast(ip.data, ip.src)

    def disp_auth(self, data):
        packet = eigrp_packet()
        payload = packet.parse(data)
        if packet.optcode == eigrp_packet.EIGRP_OPTCODE_HELLO:
            tlv = eigrp_tlv()
            while True:
                payload = tlv.parse(payload)
                if tlv.type == eigrp_tlv.EIGRP_TYPE_AUTH:
                    parent.auth = tlv
                    parent.log("EIGRP: Got authentication data from " + socket.inet_ntoa(self.address))
                    self.running = False
                    break
                if not payload:
                    break

    def disp_multicast(self, data, src):
        #print "disp_multicast from " + socket.inet_ntoa(src)
        pass
        
    def disp_unicast(self, data, src):
        #print "disp_unicast from " + socket.inet_ntoa(src)
        if src not in self.parent.peers:
            self.parent.add_peer(src, data)
        else:
            self.parent.peers[src].input(data)

    def run(self):
        self.listen()
        self.parent.log("EIGRP: Listen thread on %s terminated" % (self.interface))

    def quit(self):
        self.running = False
        #if self.isAlive():
        #    self.join()

class eigrp_peer(threading.Thread):
    def __init__(self, parent, interface, peer, as_num, auth=None, spoof=None):
        threading.Thread.__init__(self)
        self.parent = parent
        self.sem = threading.Semaphore()
        self.interface = interface
        self.peer = peer
        self.as_num = as_num
        self.sock = None
        self.msg = None
        #self.msg = eigrp_packet(eigrp_packet.EIGRP_OPTCODE_UPDATE, eigrp_packet.EIGRP_FLAGS_INIT, 0, 0, 1, [])
        self.running = True
        self.seq_num = 0
        self.auth = auth
        self.spoof = spoof

    def send(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, EIGRP_PROTOCOL_NUMBER)
        self.sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, self.interface)
        if self.spoof:
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        while self.running:
            self.sem.acquire()
            if self.msg:
                if self.auth:
                    self.msg.data.insert(0, self.auth)
                if not self.msg.optcode == eigrp_packet.EIGRP_OPTCODE_HELLO:
                    self.msg.seq_num = self.seq_num
                    self.seq_num += 1
                try:
                    data = self.msg.render()
                except:
                    self.parent.log("EIGRP: Error while sending msg to %s. Check arguments." % (self.peer))
                else:
                    if not self.spoof:
                        self.sock.sendto(data, (socket.inet_ntoa(self.peer),0))
                    else:
                        ip = struct.pack("!BBHHHBBH", 0x45, 0xc0, len(data) + 20, 0x0000, 0x0000, 0x02, EIGRP_PROTOCOL_NUMBER, 0x0000) + self.spoof + self.peer
                        ip = ip[:10] + struct.pack("!H", ichecksum_func(ip)) + ip[12:]
                        self.sock.sendto(ip + data, (socket.inet_ntoa(self.peer),0))
                self.msg = None
            self.sem.release()
            time.sleep(1)
        self.sock.close()

    def input(self, data):
        packet = eigrp_packet()
        payload = packet.parse(data)
        if not packet.optcode == eigrp_packet.EIGRP_OPTCODE_HELLO:
            reply = eigrp_packet(eigrp_packet.EIGRP_OPTCODE_HELLO, 0, 0, packet.seq_num, self.as_num)
            self.sem.acquire()
            self.msg = reply
            self.sem.release()

    def update(self, msg):
        self.sem.acquire()
        self.msg = msg
        self.sem.release()
        
    def run(self):
        iter = self.parent.liststore.append([socket.inet_ntoa(self.peer), socket.inet_ntoa(self.peer)])
        self.send()
        self.parent.log("EIGRP: Peer " + socket.inet_ntoa(self.peer) + " terminated")
        self.parent.liststore.remove(iter)
        del self.parent.peers[self.peer]

    def quit(self):
        self.running = False

class eigrp_goodbye(threading.Thread):
    def __init__(self, parent, peer, as_num):
        threading.Thread.__init__(self)
        self.parent = parent
        self.peer = peer
        self.as_num = as_num
        self.running = True

    def run(self):
        params = eigrp_param(255, 255, 255, 255, 255, 15)
        version = eigrp_version() #(0xc02, 0x300)
        args = [params, version]
        msg = eigrp_packet(eigrp_packet.EIGRP_OPTCODE_HELLO, 0, 0, 0, self.as_num, args)
        while self.running:
            self.parent.peers[self.peer].update(msg)
            self.parent.goodbye_progressbar.pulse()
            time.sleep(1)
        self.parent.log("EIGRP: Goodbye thread terminated")

    def quit(self):
        self.running = False
        
### MODULE_CLASS ###

class mod_class(object):
    def __init__(self, parent, platform):
        self.parent = parent
        self.platform = platform
        self.name = "eigrp"
        self.gladefile = "modules/module_eigrp.glade"
        self.liststore = gtk.ListStore(str, str) #gtk.ListStore(gtk.gdk.Pixbuf, str)
        self.listen_thread = None
        self.hello_thread = None
        self.goodbye_thread = None
        self.filter = False
        self.spoof = False
        self.interface = None
        self.auth = None
        self.as_num = None
        self.peers = {}

    def get_root(self):
        self.glade_xml = gtk.glade.XML(self.gladefile)
        dic = { "on_listen_togglebutton_toggled" : self.on_listen_togglebutton_toggled,
                "on_hello_togglebutton_toggled" : self.on_hello_togglebutton_toggled,
                "on_spoof_togglebutton_toggled" : self.on_spoof_togglebutton_toggled,
                "on_goodbye_button_clicked" : self.on_goodbye_button_clicked,
                "on_add_button_clicked" : self.on_add_button_clicked,
                "on_del_button_clicked" : self.on_del_button_clicked,
                "on_clear_button_clicked" : self.on_clear_button_clicked,
                "on_update_button_clicked" : self.on_update_button_clicked,
                "on_stop_button_clicked" : self.on_stop_button_clicked
                }
        self.glade_xml.signal_autoconnect(dic)

        self.listen_tooglebutton = self.glade_xml.get_widget("listen_tooglebutton")
        self.hello_togglebutton = self.glade_xml.get_widget("hello_togglebutton")
        self.spoof_togglebutton = self.glade_xml.get_widget("spoof_togglebutton")

        self.interface_entry = self.glade_xml.get_widget("interface_entry")
        self.as_entry = self.glade_xml.get_widget("as_entry")
        self.spoof_entry = self.glade_xml.get_widget("spoof_entry")

        self.update_textview = self.glade_xml.get_widget("update_textview")
        
        self.treeview = self.glade_xml.get_widget("neighbor_treeview")
        self.treeview.set_model(self.liststore)
        self.treeview.set_headers_visible(True)

        column = gtk.TreeViewColumn()
        column.set_title("Hosts")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', 1)
        self.treeview.append_column(column)

        self.goodbye_window = self.glade_xml.get_widget("goodbye_window")
        #self.goodbye_window.set_parent(self.parent.window)
        self.goodbye_label = self.glade_xml.get_widget("goodbye_label")
        self.goodbye_progressbar = self.glade_xml.get_widget("goodbye_progressbar")

        return self.glade_xml.get_widget("root")

    def set_log(self, log):
        self.log = log

    def shutdown(self):
        if self.listen_thread:
            if self.listen_thread.running:
                self.listen_thread.quit()
        if self.hello_thread:
            if self.hello_thread.running:
                self.hello_thread.quit()
        if self.goodbye_thread:
            if self.goodbye_thread.running:
                self.goodbye_thread.quit()
        for i in self.peers:
          self.peers[i].quit()  
        
    # PEER HANDLING #

    def add_peer(self, src, data=None):
        self.log("EIGRP: Got new peer " + socket.inet_ntoa(src))
        self.peers[src] = eigrp_peer(self, self.interface, src, self.as_num, self.auth, self.spoof)
        self.peers[src].start()
        if data:
            self.peers[src].input(data)
            
    # SIGNALS #

    def on_listen_togglebutton_toggled(self, btn):
        if btn.get_property("active"):
            #check for interface
            self.interface = self.interface_entry.get_text()
            try:
                self.address = get_ip_address(self.interface)
            except:
                self.log("EIGRP: Can't get address from interface %s" % (self.interface))
                return
            self.interface_entry.set_property("sensitive", False)
            self.as_num = int(self.as_entry.get_text())
            self.as_entry.set_property("sensitive", False)
            if not self.filter:
                self.log("EIGRP: Setting lokal packet filter for EIGRP")
                os.system("iptables -A INPUT -i %s -p %i -j DROP" % (self.interface, EIGRP_PROTOCOL_NUMBER))
                self.filter = True
            try:
                self.spoof_togglebutton.set_property("sensitive", False)
                if self.spoof_togglebutton.get_property("active"):
                    self.listen_thread = eigrp_listener(self, self.interface, self.spoof)
                else:
                    self.listen_thread = eigrp_listener(self, self.interface, self.address)
            except Exception, e:
                    self.log("EIGRP: Cant start listening on %s: %s" % (self.interface, e))
                    if not self.hello_togglebutton.get_property("active"):
                        self.spoof_togglebutton.set_property("sensitive", True)
                        self.as_entry.set_property("sensitive", True)
                        self.interface_entry.set_property("sensitive", True)
                    return

            self.listen_thread.start()
            self.log("EIGRP: Listen thread on %s started" % (self.interface))
        
        else:
            self.listen_thread.quit()
            if self.filter:
                self.log("EIGRP: Removing lokal packet filter for EIGRP")
                os.system("iptables -D INPUT -i %s -p %i -j DROP" % (self.interface, EIGRP_PROTOCOL_NUMBER))
                self.filter = False

            if not self.hello_togglebutton.get_property("active"):
                self.spoof_togglebutton.set_property("sensitive", True)
                self.as_entry.set_property("sensitive", True)
                self.interface_entry.set_property("sensitive", True)


    def on_hello_togglebutton_toggled(self, btn):
        if btn.get_property("active"):
            #check for interface
            self.interface = self.interface_entry.get_text()
            try:
                self.address = get_ip_address(self.interface)
            except:
                self.log("EIGRP: Can't get address from interface %s" % (self.interface))
                return
            self.interface_entry.set_property("sensitive", False)
            self.as_num = int(self.as_entry.get_text())
            self.as_entry.set_property("sensitive", False)
            try:
                self.spoof_togglebutton.set_property("sensitive", False)
                if self.spoof_togglebutton.get_property("active"):
                    self.hello_thread = eigrp_hello_thread(self, self.interface, self.as_num, self.auth, self.spoof)
                else:
                    self.hello_thread = eigrp_hello_thread(self, self.interface, self.as_num, self.auth, self.address)
            except Exception, e:
                    self.log("EIGRP: Cant start hello thread on %s: %s" % (self.interface, e))
                    if not self.listen_togglebutton.get_property("active"):
                        self.spoof_togglebutton.set_property("sensitive", True)
                        self.as_entry.set_property("sensitive", True)
                        self.interface_entry.set_property("sensitive", True)
                    return
        
            self.hello_thread.start()
            self.log("EIGRP: Hello thread on %s started" % (self.interface))
        else:
            self.hello_thread.quit()
            if not self.listen_togglebutton.get_property("active"):
                self.spoof_togglebutton.set_property("sensitive", True)
                self.as_entry.set_property("sensitive", True)
                self.interface_entry.set_property("sensitive", True)

    def on_spoof_togglebutton_toggled(self, btn):
        if btn.get_property("active"):
            self.spoof = socket.inet_aton(self.spoof_entry.get_text())
            self.spoof_entry.set_property("sensitive", False)
        else:
            self.spoof_entry.set_property("sensitive", True)
            self.spoof = None

    def on_goodbye_button_clicked(self, data):
        select = self.treeview.get_selection()
        (model, paths) = select.get_selected_rows()
        if len(paths) == 1:
            host = model.get_value(model.get_iter(paths[0]), 1)
            self.goodbye_thread = eigrp_goodbye(self, socket.inet_aton(host), self.as_num)
            self.goodbye_label.set_label("Sending Goodbye Messages to %s..." % (host))
            self.goodbye_window.show_all()
            self.goodbye_thread.start()
            self.log("EIGRP: Goodbye thread started for %s" % (host)) 

    def on_add_button_clicked(self, data):
        dialog = gtk.MessageDialog(self.parent.window, gtk.DIALOG_MODAL | gtk.DIALOG_DESTROY_WITH_PARENT, gtk.MESSAGE_QUESTION, gtk.BUTTONS_OK_CANCEL, "Enter IP Address to add:")
        entry = gtk.Entry(0)
        dialog.vbox.pack_start(entry)
        entry.show()
        ret = dialog.run()
        dialog.destroy()
        if ret == gtk.RESPONSE_OK:
            try:
                peer = entry.get_text()
                self.add_peer(socket.inet_aton(peer))
            except Exception, e:
                self.log("EIGRP: Cant add peer %s: %s" % (peer, e))

    def on_del_button_clicked(self, data):
        select = self.treeview.get_selection()
        (model, paths) = select.get_selected_rows()
        for i in paths:
            host = model.get_value(model.get_iter(i), 1)
            peer = socket.inet_aton(host)
            self.peers[peer].quit()

    def on_clear_button_clicked(self, data):
        #self.liststore.clear()
        for i in self.peers:
            self.peers[i].quit()

    def on_update_button_clicked(self, data):
        buffer = self.update_textview.get_buffer()
        text = buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter())
        if text != "":
            exec("msg = " + text)
            select = self.treeview.get_selection()
            (model, paths) = select.get_selected_rows()
            for i in paths:
                host = model.get_value(model.get_iter(i), 1)
                self.log("EIGRP: Sending update to %s" % (host))
                peer = socket.inet_aton(host)
                self.peers[peer].update(msg)
        
    def on_stop_button_clicked(self, data):
        self.goodbye_thread.quit()
        self.goodbye_window.hide_all()