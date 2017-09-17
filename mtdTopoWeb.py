#!/usr/bin/python
# sdn@ubuntu:~$ sudo mn --custom ~/mininet/custom/mtdtopo10scan.py --topo mytopo --mac --switch ovsk --controller remote
# sdn@ubuntu:~/mininet/custom$ sudo ./mtdtopo10scan.py

import os
import re
import sys

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSSwitch, Node
from mininet.util import dumpNodeConnections
from mininet.link import TCLink, Intf
from mininet.log import setLogLevel, info, error
from mininet.cli import CLI
from mininet.util import quietRun

class LinuxRouter(Node):
    def config(self, **params):
        super(LinuxRouter, self).config(**params)
        self.cmd('sysctl net.ipv4.ip_forward=1')

    def terminate(self):
        self.cmd('sysctl net.ipv4.ip_forward=0')
        super(LinuxRouter, self).terminate()


class mtdTopo(Topo):
    ''' [h1,hn] -- s1 -- Router -- [atk,Intf]'''

    def __init__(self, n=10, **opts):
        Topo.__init__(self, **opts)

        defaultGW = '10.0.0.254/23'

        s1, s2 = [self.addSwitch(s) for s in 's1', 's2']
        # s1 = self.addSwitch('s1')

        for h in range(1, n + 1):
            network = '10.0.0.'
            ipHost = '%s' % h
            cidr = '/23'
            ipAddress = network + ipHost + cidr
            host = 'h%s' % h
            self.addHost(host, ip=ipAddress, defaultRoute='via 10.0.0.254')  # % defaultGW)
            self.addLink(host, s1)

        router = self.addNode('r0', cls=LinuxRouter, ip=defaultGW)
        self.addLink(s1, router, intfName2='r0-eth1', params2={'ip': defaultGW})
        self.addLink(s2, router, intfName2='r0-eth2', params2={'ip': '172.16.0.254/24'})
        #self.addLink(s2, Intf, intfName2='enp8s0', params2={'ip':'172.16.0.1/24'})

        atk = self.addHost('atk', ip='172.16.0.2/24', defaultRoute='via 172.16.0.254')
        self.addLink(atk, s2)

        intfName = sys.argv[1] if len(sys.argv) > 1 else 'enp8s0'
        self.Intf(intfName, node=s2)
        '''
          File "/home/adrux/Documents/git/IPMTD/mtdTopoWeb.py", line 246, in <module>
            run()
          File "/home/adrux/Documents/git/IPMTD/mtdTopoWeb.py", line 92, in run
            topo = mtdTopo(n=10)
          File "/home/adrux/Documents/git/IPMTD/mtdTopoWeb.py", line 57, in __init__
            self.Intf(intfName, node=s2)
        AttributeError: 'mtdTopo' object has no attribute 'Intf'
        '''

    '''
    Mininet Example Code for connecting hardware interfaces to vswitch
    https://github.com/mininet/mininet/blob/master/examples/hwintf.py

    def checkIntf(intf):
        "Make sure intf exists and is not configured."
        config = quietRun('ifconfig %s 2>/dev/null' % intf, shell=True)
        if not config:
            error('Error:', intf, 'does not exist!\n')
            exit(1)
        ips = re.findall(r'\d+\.\d+\.\d+\.\d+', config)
        if ips:
            error('Error:', intf, 'has an IP address,'
                                  'and is probably in use!\n')
            exit(1)

        intfName = sys.argv[1] if len(sys.argv) > 1 else 'eth1'
        info('*** Connecting to hw intf: %s' % intfName)

        info('*** Checking', intfName, '\n')

        checkIntf(intfName)
        _intf = Intf(intfName, node=s2)
    '''

topos = {'mytopo': (lambda: mtdTopo())}


def run():
    "Create and test the network"
    topo = mtdTopo(n=10)
    net = Mininet(topo=topo, controller=RemoteController)

    net.start()

    print "** Dumping host connections **"
    dumpNodeConnections(net.hosts)

    atk = net.get('atk')
    atk.cmd('sudo systemctl restart apache2 &')
    atk.cmd('sleep 2')

    h1 = net.get('h1')
    h1.cmd('ping 172.16.0.1 &')
    #h1.cmd('sudo -i google-chrome --incognito --no-sandbox')
    #h1.cmd('sleep 5')
    #h1.cmd('sudo -i -u adrux chromium-browser --incognito')


    '''
    print "Testing bandwith"
    h1, h2 = net.get('h1','h2')
    net.iperf((h1, h2))
    '''
    #nhosts = 10
    #hosts = net.hosts

    '''
    for h in hosts:
        if str(h) != 'atk' and str(h) != 'r0':
            print " "
            print "Start HTTP Server Port 80 on Host " + str(h)
            h.cmd('python -m SimpleHTTPServer 80 &')
            h.cmd('sleep 1')
            # print h
            print "HTTPServer UP in " + str(h)
            h.cmd('ping 172.16.0.1 &')
            print str(h) + " ping atk"
            print " "
    '''

    '''
        for h in range(1, nhosts + 1):
            h = net.get(h)
            h.cmd('python -m SimpleHTTPServer 80 &')
            h.cmd('sleep 1')
            print h
            print "** HTTPServer UP in host **"
            h.cmd('ping 172.16.0.1')
            print "Host ping atk"
    '''

    '''
    for h in hosts:
        atk.cmd('ping ', h.IP() + ' -c 2 &' )
    '''

    '''
    print "** Scanning network **"

    atk.cmd(
        "sudo nmap -n -Pn -p T:80 10.0.0.0/25 --max-rtt-timeout 100ms --max-retries 1 --host-timeout 30s --exclude 10.0.0.254 -oG ~/Documents/TFIA/Scans/outputnmap")
    atk.cmd('sleep 1')

    # -sS -Pn -n 
    # -sS = TCP SYN scan
    # -Pn = no Ping scan
    # -n = no DNS resolution
    # -PS = -PS80 selects TCP Port -p T:80
    # -oG = output grepable ( #--append-output)
    # timeout options = --max-rtt-timeout 100ms --max-retries 1 --host-timeout 30s 
    # Nmap 7.01 scan initiated Wed May 17 20:47:35 2017 as: nmap -oG ~/Documents/TFIA/Scans/OutputScan -p T:80 10.0.0.0/24
    # Host: 10.0.0.10 ()	Status: Up
    # Host: 10.0.0.10 ()	Ports: 80/closed/tcp//http///
    # Host: 10.0.0.203 ()	Status: Up
    # Host: 10.0.0.203 ()	Ports: 80/closed/tcp//http///
    # Nmap done at Wed May 17 20:48:22 2017 -- 256 IP addresses (2 hosts up) scanned in 46.25 seconds

    # print "** Scan = " + atk.cmd("egrep 'Ports' ~/Documents/TFIA/Scans/outputnmap")
    atk.cmd('sleep 1')

    print "** Scan = " + atk.cmd("egrep 'seconds' ~/Documents/TFIA/Scans/outputnmap")
    atk.cmd('sleep 1')

    # Nmap done at Wed May 17 20:48:22 2017 -- 256 IP addresses (2 hosts up) scanned in 46.25 seconds

    print "** Get alive hosts on port 80 **"
    atk.cmd(
        "egrep '[^0-9]80/open' ~/Documents/TFIA/Scans/outputnmap > ~/Documents/TFIA/Scans/open80; awk '{print $2;}' ~/Documents/TFIA/Scans/open80 > ~/Documents/TFIA/Scans/outputnmapIP80")
    atk.cmd('sleep 1')

    # Host: 10.0.0.10 ()	Ports: 80/open/tcp//http///
    # Host: 10.0.0.203 ()	Ports: 80/open/tcp//http///

    # 10.0.0.10
    # 10.0.0.203

    #    print " Alive Hosts = " + atk.cmd("egrep -c [^0-9]80/open' ~/Documents/TFIA/Scans/outputnmap")

    # print "** Alive hosts: " + "\n" + atk.cmd("egrep '[^0-9]80/open' ~/Documents/TFIA/Scans/outputnmap")
    atk.cmd('sleep 1')

    print ""

    print "** Total hosts up = " + atk.cmd("egrep -c '[^0-9]80/open' ~/Documents/TFIA/Scans/outputnmap")
    atk.cmd('sleep 1')

    # agrega http://$IP y prepara archivo para lectura de wget

    atk.cmd(
        "awk '{print \"http://\"$0}' ~/Documents/TFIA/Scans/outputnmapIP80 > ~/Documents/TFIA/Scans/outputnmapIP80URL")
    atk.cmd('sleep 1')

    # http://10.0.0.10
    # http://10.0.0.203

    print ""

    print "** Get HTTP on Protected Network **"

    # -i --input-file=file Read url from file    
    # -a --append-output=logfile

    atk.cmd(
        "wget --spider --tries=1 --connect-timeout=2 -i ~/Documents/TFIA/Scans/outputnmapIP80URL -a ~/Documents/TFIA/Scans/HTTP_Results -P ~/Documents/TFIA/Scans/delete")
    atk.cmd('sleep 1')

    atk.cmd("egrep 'HTTP request sent' ~/Documents/TFIA/Scans/HTTP_Results > ~/Documents/TFIA/Scans/Connections")
    atk.cmd('sleep 1')

    # atk.cmd("cat ~/Documents/TFIA/Scans/Connections |sort|uniq|less > ~/Documents/TFIA/Scans/S_ConnsSorted")
    # atk.cmd('sleep 1')

    print "** Successful Connections Port 80 = " + atk.cmd(
        "egrep 'HTTP request sent' ~/Documents/TFIA/Scans/HTTP_Results | wc -l")
    atk.cmd('sleep 1')

    atk.cmd(
        "egrep 'HTTP request sent' ~/Documents/TFIA/Scans/HTTP_Results | wc -l >> ~/Documents/TFIA/Scans/Successful_ConnectionsTFIA")
    atk.cmd('sleep 1')

    atk.cmd(
        "cd ~/Documents/TFIA/Scans/; rm Connections open80 outputnmapIP80 S_Connsu HTTP_Results outputnmap outputnmapIP80URL S_ConnsSorted")
    # atk.cmd('sleep 1')
    '''

    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    # topo = mtdTopo()
    # net = Mininet( topo=topo, controller=RemoteController )
    run()
