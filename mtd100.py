# Python
import collections
import random
import struct
import array

# Ryu
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3, ether
from ryu.lib import addrconv
from ryu.lib.packet import packet, ethernet, arp, ipv4

# IP network
from netaddr import IPNetwork


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.rip_to_vip = {}  # {dpid:{rip:vip, ...}}
        self.vip_to_weigth = {}  # {dpid:{vip:weight}}
        self.mac_to_port = {}

        network = IPNetwork('10.0.0.0/23')  # Bloque de 1024 direcciones IP
        for ip in network:
            if (ip > IPNetwork('10.0.0.10')):
                self.vip_to_weigth[str(ip)] = 5
            else:
                self.rip_to_vip[str(ip)] = '0'

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]

        self.add_flow(datapath, 0, 0, match, actions)

    def add_flow(self, datapath, hard_timeout, priority, match, actions, buffer_id=None):

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, hard_timeout=hard_timeout, priority=priority,
                                    match=match, instructions=inst, buffer_id=buffer_id)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, hard_timeout=hard_timeout,
                                    priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    # Virtual IP MTD
    def selectVip(self, host_number, max_weight):

        '''
        Recibe el numero de hosts y el peso maximo para las mutaciones.
        El peso maximo es la cantidad de iteraciones del MTD antes de que
        la vip se vuelva a utilizar. El peso es elegido por el usuario.

        :type max_weight: object

        '''

        vip_array = []  # Returns array to packet_in_handler

        ' Al inicio de cada iteracion aumenta el peso en 1 '
        for key, value in self.vip_to_weigth.items():
            if value < max_weight:
                self.vip_to_weigth[key] = value + 1

        while True:
            for i in range(host_number):
                ' Elige max_weight maximo disponible '
                while not (max_weight in self.vip_to_weigth.values()) and max_weight > 0:
                    max_weight -= 1

                random_vip = random.choice(self.vip_to_weigth.keys())

                while max_weight != self.vip_to_weigth[random_vip]:
                    ' Itera entre las vip al azar hasta encontrar una con max_weight correcto '
                    random_vip = random.choice(self.vip_to_weigth.keys())
                    assert isinstance(random_vip, object)
                    # Ques es un assert?
                    #self.logger.info("\n" + "random_vip = %s" + "\n\n", random_vip)
                vip_array.append(random_vip)  # Guarda vip en array para enviar a rip_to_vip
                self.vip_to_weigth[random_vip] = 0  # Modifica peso de vip para que no se elija en proximas iteraciones

            if host_number == len(vip_array):
                break

        return vip_array, self.vip_to_weigth

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        # If you hit this you might want to increase
        # the "miss_send_length" of your switch

        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id

        pkt = packet.Packet(array.array('B', msg.data))
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        ip4_pkt = pkt.get_protocol(ipv4.ipv4)

        mac_src = eth_pkt.src
        mac_dst = eth_pkt.dst
        src = None

        if arp_pkt:
            src = arp_pkt.src_ip
            arp_dst = arp_pkt.dst_ip

        elif ip4_pkt:
            src = ip4_pkt.src
            ip4_dst = ip4_pkt.dst

        else:
            ip4_src = ''
            ip4_dst = ''

        gateway = '10.0.0.254'
        ipv4_ext = '172.16.0.1'
        vIP = ''

        self.mac_to_port.setdefault(dpid, {}) # dpid le asigno el par mac y puerto 1, {AA:AA:AA, 1}

        ' Llena tabla de MACs '

        ' learn a mac address to avoid FLOOD next time '
        self.mac_to_port[dpid][mac_src] = in_port
        if mac_dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][mac_dst]
            assert isinstance(out_port, object)
            self.logger.info("\n" + "MAC in table -> out_port %s", out_port)
        else:
            out_port = ofproto.OFPP_FLOOD
            self.logger.info("\n" + "No MAC in table -> FLOOD")

        match = parser.OFPMatch(
            in_port=in_port, eth_dst=mac_dst, eth_type=0x0806
        )
        actions = [parser.OFPActionOutput(out_port)]
        self.add_flow(
            datapath, 0, 1, match, actions
        )

        ' Mapear rIp to vIP en un diccionario {rIp:vIP} '

        vip_array, _vip_to_weigth = self.selectVip(10, 5)  # hosts y max_weight para MTD
        i = 0
        for key in self.rip_to_vip:
            self.rip_to_vip[key] = vip_array[i]
            if int(len(vip_array)) >> i:
                i += 1

        if src in self.rip_to_vip.keys() and out_port != ofproto.OFPP_FLOOD and dpid == 2:
            ' Si ip_src es una ip real. Redes externas no estan en el diccionario '
            #self.logger.info("\n" + "If ip4_src es real")
            vIP = self.rip_to_vip[src]  # asigna el valor del key a vIP
            self.logger.info("\n" + "vIP = %s", vIP)
            self.logger.info("\n" + "ip4_src = %s" + "\n\n", src)
            set_out_port = parser.OFPActionOutput(out_port)
            set_in_port = parser.OFPActionOutput(in_port)

            ' Modifica src a vIP'
            set_field_vIP = parser.OFPActionSetField(
                ipv4_src=str(vIP)
            )

            ' Devuelve src a su IP original'
            set_field_rIP = parser.OFPActionSetField(
                ipv4_dst=str(src)
            )

            ' Flow 1 = Conexiones salientes = modifica IP fuente por IP virtual'
            match = parser.OFPMatch(
                in_port=in_port, eth_dst=mac_dst, eth_type=0x0800, ipv4_src=str(src), ipv4_dst=str(ipv4_ext)
            )
            actions = (set_field_vIP, set_out_port)
            self.add_flow(
                datapath, 0, 3, match, actions
            )
            ' Flow 2 Conexiones entrantes = modifica IP destino por IP real'
            match = parser.OFPMatch(
                in_port=out_port, eth_dst=mac_src, eth_type=0x0800, ipv4_src=str(ipv4_ext), ipv4_dst=str(vIP)
            )
            actions = (set_field_rIP, set_in_port)
            self.add_flow(
                datapath, 0, 3, match, actions
            )

        else:
            pass

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)

        datapath.send_msg(out)
