#!/usr/bin/python

from mininet.node import RemoteController, OVSKernelSwitch, Host
from mininet.log import setLogLevel, info
from mn_wifi.cli import CLI
from mn_wifi.net import Mininet_wifi
from mn_wifi.node import OVSKernelAP


def topology():
    net = Mininet_wifi(ipBase="10.0.0.0/8")

    info("*** Adding controller\n")
    c1 = net.addController(name="c1",
                           controller=RemoteController,
                           protocol="tcp",
                           ip="127.0.0.1",
                           port=6653)

    info("*** Adding access points\n")
    ap1 = net.addAccessPoint("ap1", cls=OVSKernelAP, ssid="ssid-ap1", client_isolation=True,
                             mac="00:00:00:00:AC:01", dpid="00:00:00:00:00:00:AC:01",
                             channel="1", position="15,30,0", protocols="OpenFlow13")
    ap2 = net.addAccessPoint("ap2", cls=OVSKernelAP, ssid="ssid-ap2", client_isolation=True,
                             mac="00:00:00:00:AC:02", dpid="00:00:00:00:00:00:AC:02",
                             channel="6", position="55,30,0", protocols="OpenFlow13")
    ap3 = net.addAccessPoint("ap3", cls=OVSKernelAP, ssid="ssid-ap3", client_isolation=True,
                             mac="00:00:00:00:AC:03", dpid="00:00:00:00:00:00:AC:03",
                             channel="1", position="95,30,0", protocols="OpenFlow13")

    info("*** Adding stations\n")
    sta1 = net.addStation("sta1", ip="10.0.0.1", mac="00:00:00:00:00:01", position="10,30,0")
    sta2 = net.addStation("sta2", ip="10.0.0.2", mac="00:00:00:00:00:02", position="20,40,0")
    sta3 = net.addStation("sta3", ip="10.0.0.3", mac="00:00:00:00:00:03", position="50,40,0")
    sta4 = net.addStation("sta4", ip="10.0.0.4", mac="00:00:00:00:00:04", position="90,20,0")

    info("*** Adding switches\n")
    s1 = net.addSwitch("s1", cls=OVSKernelSwitch, dpid="00:00:00:00:00:00:00:01", protocols="OpenFlow13")
    s2 = net.addSwitch("s2", cls=OVSKernelSwitch, dpid="00:00:00:00:00:00:00:02", protocols="OpenFlow13")
    s3 = net.addSwitch("s3", cls=OVSKernelSwitch, dpid="00:00:00:00:00:00:00:03", protocols="OpenFlow13")
    s4 = net.addSwitch("s4", cls=OVSKernelSwitch, dpid="00:00:00:00:00:00:00:04", protocols="OpenFlow13")
    s5 = net.addSwitch("s5", cls=OVSKernelSwitch, dpid="00:00:00:00:00:00:00:05", protocols="OpenFlow13")
    s6 = net.addSwitch("s6", cls=OVSKernelSwitch, dpid="00:00:00:00:00:00:00:06", protocols="OpenFlow13")
    s7 = net.addSwitch("s7", cls=OVSKernelSwitch, dpid="00:00:00:00:00:00:00:07", protocols="OpenFlow13")

    info("*** Adding hosts\n")
    h1 = net.addHost("h1", cls=Host, ip="10.0.1.1", defaultRoute=None, mac="00:00:00:00:01:01")
    h2 = net.addHost("h2", cls=Host, ip="10.0.1.2", defaultRoute=None, mac="00:00:00:00:01:02")
    h3 = net.addHost("h3", cls=Host, ip="10.0.1.3", defaultRoute=None, mac="00:00:00:00:01:03")

    net.setPropagationModel(model="logDistance", exp=5)

    info("*** Configuring wifi nodes\n")
    net.configureWifiNodes()

    info("*** Creating links\n")
    net.addLink(ap1, s1)
    net.addLink(ap2, s3)
    net.addLink(ap3, s5)

    net.addLink(s1, s2)
    net.addLink(s2, s6)
    net.addLink(s3, s4)
    net.addLink(s4, s7)
    net.addLink(s4, s6)
    net.addLink(s5, s7)
    net.addLink(s6, s7)

    net.addLink(s2, h1)
    net.addLink(s6, h2)
    net.addLink(s7, h3)

    net.plotGraph(max_x=100, max_y=100)

    info("*** Starting network\n")
    net.build()
    c1.start()
    ap1.start([c1])
    ap2.start([c1])
    ap3.start([c1])
    s1.start([c1])
    s2.start([c1])
    s3.start([c1])
    s4.start([c1])
    s5.start([c1])
    s6.start([c1])
    s7.start([c1])

    info("*** Running CLI\n")
    CLI(net)

    info("*** Stopping network\n")
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    topology()
