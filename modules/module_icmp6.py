#       module_ipv6.py
#       
#       Copyright 2010 Daniel Mende <dmende@ernw.de>
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

import threading

import dnet
import dpkt

import gobject
import gtk
import gtk.glade
import struct

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

class ipv6_header(object):

   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   #~ |Version| Traffic Class |           Flow Label                  |
   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   #~ |         Payload Length        |  Next Header  |   Hop Limit   |
   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   #~ |                                                               |
   #~ +                                                               +
   #~ |                                                               |
   #~ +                         Source Address                        +
   #~ |                                                               |
   #~ +                                                               +
   #~ |                                                               |
   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   #~ |                                                               |
   #~ +                                                               +
   #~ |                                                               |
   #~ +                      Destination Address                      +
   #~ |                                                               |
   #~ +                                                               +
   #~ |                                                               |
   #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    
    def __init__(self, version=None, tclass=None, label=None, nh=None, hops=None, src=None, dst=None):
        self.version = version
        self.tclass = tclass
        self.label = label
        self.nh = nh
        self.hops = hops
        self.src = src
        self.dst = dst

    def parse(self, data):
        (ver_class_label, length, self.nh, self.hops, self.src, self.dst) = struct.unpack("!IHBB16s16s", data[:40])
        self.version = ver_class_label >> 28
        self.tclass = (ver_class_label >> 20) & 0x0ff
        self.label = ver_class_label & 0x000fffff
        return data[40:]

    def render(self, data):
        ver_class_label = self.version << 28
        ver_class_label += self.tclass << 20
        ver_class_label += self.label
        return struct.pack("!IHBB16s16s", ver_class_label, len(data), self.nh, self.hops, self.src, self.dst) + data

class icmp6_header(object):
    
    #~  0                   1                   2                   3
    #~  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #~ |     Type      |     Code      |          Checksum             |
    #~ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #~ |                                                               |
    #~ +                         Message Body                          +
    #~ |                                                               |
    
    def __init__(self, type=None, code=None):
        self.type = type
        self.code = code

    def parse(self, data):
        (self.type, self.code, self.csum) = struct.unpack("!BBH", data[:4])
        return data[4:]
        
    def render(self, data):
        ret = struct.pack("!BBH", self.type, self.code, 0) + data
        ret[3:4] = ichecksum_func(ret)
        return ret

class mod_class(object):
    NEIGH_MAC_ROW = 0
    NEIGH_IP_ROW = 1
    NEIGH_STATE_ROW = 2
    
    SPECIAL_IP_ROW = 0
    SPECIAL_TYPE_ROW = 1
    
    def __init__(self, parent, platform):
        self.parent = parent
        self.platform = platform
        self.name = "icmp6"
        self.gladefile = "/modules/module_icmp6.glade"
        self.neigh_liststore = gtk.ListStore(str, str, str)
        self.special_treestore = gtk.TreeStore(str, str)
        self.neigh = {}
        self.special = {}

    def start_mod(self):
        pass
    
    def shut_mod(self):
        self.neigh_liststore.clear()
        self.special_treestore.clear()
        self.neigh = {}
        self.special = {}

    def get_root(self):
        self.glade_xml = gtk.glade.XML(self.parent.data_dir + self.gladefile)
        dic = { }
        self.glade_xml.signal_autoconnect(dic)

        self.neigh_treeview = self.glade_xml.get_widget("neigh_treeview")
        self.neigh_treeview.set_model(self.neigh_liststore)
        self.neigh_treeview.set_headers_visible(True)
        
        column = gtk.TreeViewColumn()
        column.set_title("MAC")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.NEIGH_MAC_ROW)
        self.neigh_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("IP")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.NEIGH_IP_ROW)
        self.neigh_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        column.set_title("STATE")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.NEIGH_STATE_ROW)
        self.neigh_treeview.append_column(column)
        
        
        self.special_treeview = self.glade_xml.get_widget("special_treeview")
        self.special_treeview.set_model(self.special_treestore)
        #self.special_treeview.set_headers_visible(True)
        self.special_treeview.set_headers_visible(False)
        
        column = gtk.TreeViewColumn()
        #column.set_title("IP")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.SPECIAL_IP_ROW)
        self.special_treeview.append_column(column)
        column = gtk.TreeViewColumn()
        #column.set_title("")
        render_text = gtk.CellRendererText()
        column.pack_start(render_text, expand=True)
        column.add_attribute(render_text, 'text', self.SPECIAL_TYPE_ROW)
        self.special_treeview.append_column(column)
        
        return self.glade_xml.get_widget("root")

    def log(self, msg):
        self.__log(msg, self.name)

    def set_log(self, log):
        self.__log = log

    def get_eth_checks(self):
        return (self.check_eth, self.input_eth)
    
    def check_eth(self, eth):
        if eth.type == dpkt.ethernet.ETH_TYPE_IP6:
            return (True, False)
        return (False, False)

    def input_eth(self, eth, timestamp):
        mac = str(eth.src)
        ip6 = dpkt.ip6.IP6(eth.data)
        src_str = dnet.ip6_ntoa(ip6.src)
        if src_str != "::" and src_str not in self.neigh:
            if src_str.startswith("fe80:"):
                state = ["LinkLocal"]
            else:
                state = []
            iter = self.neigh_liststore.append([mac, src_str, ", ".join(state)])
            self.neigh[src_str] = { 'iter' : iter, 'state' : state }

        if ip6.nxt == dnet.IP_PROTO_ICMPV6:
            icmp6 = dpkt.icmp6.ICMP6(str(ip6.data))
            
            if icmp6.type == dpkt.icmp6.ND_NEIGHBOR_SOLICIT:
                pass
            elif icmp6.type == dpkt.icmp6.ND_NEIGHBOR_ADVERT:
                pass
            elif icmp6.type == dpkt.icmp6.ND_ROUTER_SOLICIT:
                self.set_special_type(src_str, "asking for router")
            elif icmp6.type == dpkt.icmp6.ND_ROUTER_ADVERT:
                self.add_neigh_state(src_str, "Router")
              
    def add_neigh_state(self, src, state):
        if src in self.neigh:
            dict = self.neigh[src]
            if state not in dict['state']:
                dict['state'].append(state)
                self.update_neigh_state(src)
    
    def del_neigh_state(self, src, state):
        if src in self.neigh:
            if state in self.neigh[src]['state']:
                self.neigh[src]['state'].remove(state)
                self.update_neigh_state(src)
                
    def update_neigh_state(self, src):
        if src in self.neigh:
            self.neigh_liststore.set(self.neigh[src]['iter'], self.NEIGH_STATE_ROW, ", ".join(self.neigh[src]['state']))
        
    def set_special_type(self, src, type, data=""):       
        dict = None
        if src not in self.special:
            root = self.special_treestore.append(None, [src, ""])
            iter = self.special_treestore.append(root, [type, data])
            dict = { 'iter' : root, type : iter}
            self.special[src] = dict
        else:
            if type_str not in self.special[src]:                        
                dict = self.special[src]
                iter = self.special_treestore.append(dict['iter'], [type, data])
                dict[type] = None
    