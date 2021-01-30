package it.unipi.floodlight;

import net.floodlightcontroller.core.*;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.*;
import net.floodlightcontroller.devicemanager.*;
import net.floodlightcontroller.packet.*;
import net.floodlightcontroller.routing.*;
import net.floodlightcontroller.topology.NodePortTuple;
import net.floodlightcontroller.util.*;
import org.projectfloodlight.openflow.protocol.*;
import org.projectfloodlight.openflow.protocol.action.*;
import org.projectfloodlight.openflow.protocol.match.*;
import org.projectfloodlight.openflow.protocol.oxm.*;
import org.projectfloodlight.openflow.types.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;


public class MobilitySupport implements IFloodlightModule, IOFMessageListener {
    private final Logger logger = LoggerFactory.getLogger(MobilitySupport.class);
    private IFloodlightProviderService floodlightProvider;
    private IOFSwitchService switchService;
    private IDeviceService deviceService;
    private IRoutingService routingService;

    // Default virtual IP and MAC addresses of the service.
    private IPv4Address SERVICE_IP = IPv4Address.of("8.8.8.8");
    private MacAddress SERVICE_MAC =  MacAddress.of("FE:FE:FE:FE:FE:FE");

    // Subscribed users.
    private final Set<MobilityUser> subscribedUsers = new HashSet<>();

    // Servers implementing the service.
    private final Set<MobilityServer> servers = new HashSet<>();

    // Access switches.
    private final Set<DatapathId> accessSwitches = new HashSet<>();

    // Flow mod timeouts (in seconds).
    private final int IDLE_TIMEOUT = 10;
    private final int HARD_TIMEOUT = 20;

    // Priority of the default rule of an access switch (must be higher than 1).
    private final int ACCESS_SWITCH_DEFAULT_RULE_PRIORITY = 10;


    @Override
    public String getName() {
        return MobilitySupport.class.getSimpleName();
    }

    @Override
    public boolean isCallbackOrderingPrereq(OFType type, String name) {
        /* The TopologyManager and DeviceManager modules must execute before the
        MobilitySupport module, to ensure that the actual topology of the network is learnt.
        */
        return (type.equals(OFType.PACKET_IN) && (name.equals("topology") || name.equals("devicemanager")));
    }

    @Override
    public boolean isCallbackOrderingPostreq(OFType type, String name) {
        /* The Forwarding module must execute after the MobilitySupport module,
         so that the latter has control over the virtualization of to the service.
        */
        return (type.equals(OFType.PACKET_IN) && (name.equals("forwarding")));
    }

    private void increasePriorityOfDefaultRule(DatapathId switchDPID) {
        /* By default, a switch sends a packet to the controller, if it has no matching rules
        for the packet. Given that the Forwarding module installs rules with priority one,
        the method installs a default rule on the specified switch with a priority higher than one,
        so that the rules installed by the Forwarding module are ignored.
        */
        IOFSwitchBackend targetSwitch = (IOFSwitchBackend) switchService.getSwitch(switchDPID);

        if (targetSwitch == null) {
            logger.error("Cannot modify the priority of the default rule of switch " + switchDPID +
                         ". The switch is not connected");
            return;
        }

        // Remove the default rule in each table.
        OFFlowDeleteStrict deleteDefaultRule = targetSwitch.getOFFactory().buildFlowDeleteStrict()
                .setTableId(TableId.ALL)
                .setOutPort(OFPort.CONTROLLER)
                .build();
        targetSwitch.write(deleteDefaultRule);

        /* Insert a new default rule in each table. The insertion is done only in the tables
        that are effectively used by the switch, which is given by getMaxTableForTableMissFlow().
        */
        ArrayList<OFAction> outputToController = new ArrayList<>(1);
        ArrayList<OFMessage> addDefaultRules = new ArrayList<>();
        outputToController.add(targetSwitch.getOFFactory().actions().output(OFPort.CONTROLLER, 0xffFFffFF));

        for (int tableId = 0; tableId <= targetSwitch.getMaxTableForTableMissFlow().getValue(); tableId++) {
            OFFlowAdd addDefaultRule = targetSwitch.getOFFactory().buildFlowAdd()
                    .setTableId(TableId.of(tableId))
                    .setPriority(ACCESS_SWITCH_DEFAULT_RULE_PRIORITY)
                    .setActions(outputToController)
                    .build();
            addDefaultRules.add(addDefaultRule);
        }
        targetSwitch.write(addDefaultRules);

        logger.info("The priority of the default rule of switch " + switchDPID +
                            " has been increased to " + ACCESS_SWITCH_DEFAULT_RULE_PRIORITY);
    }

    private boolean isAccessSwitch(DatapathId sw) {
        return accessSwitches.contains(sw);
    }

    private boolean isServiceAddress(MacAddress addressMAC, IPv4Address addressIP) {
        // Check if the given (MAC address, IP address) couple identifies the service.
        return (addressMAC.compareTo(SERVICE_MAC) == 0) && (addressIP.compareTo(SERVICE_IP) == 0);
    }

    private boolean isServerAddress(MacAddress addressMAC, IPv4Address addressIP) {
        /* Check if the given (MAC address, IP address) couple identifies a server.
        If addressIP is null, the comparison is done using only addressMAC.
        */
        return servers.contains(new MobilityServer(addressMAC, addressIP));
    }

    private boolean isSubscribedUser(MacAddress addressMAC) {
        /* Check if the given MAC address identifies a subscribed server.
        Giving a null username, the comparison is done using only addressMAC.
        */
        return subscribedUsers.contains(new MobilityUser(null, addressMAC));
    }

    private Set<SwitchPort> getSwitchesAttachedToDevice(MacAddress deviceMAC) {
        // Search based only on MAC addresses.
        logger.debug("DEVICE: " + deviceMAC); // TODO: remove
        Iterator<? extends IDevice> devices = deviceService.queryDevices(deviceMAC,
                                                                         null,
                                                                         null,
                                                                         null,
                                                                         null);
        Set<SwitchPort> attachedSwitches = new HashSet<>();
        int numberOfDevices = 0;

        while(devices.hasNext()) {
            attachedSwitches.addAll(Arrays.asList(devices.next().getAttachmentPoints()));
            numberOfDevices++;

            if (numberOfDevices > 1) {
                logger.error("Multiple devices with the same MAC address were found in the network." +
                        "Returning no attachment points.");
                break;
            }
        }

        logger.debug("Number of devices: " + numberOfDevices); // TODO:remove
        /* Conditions causing the return of no switches:
        1) the device is not in the network anymore;
        2) multiple devices with the same MAC address are found (it should not be possible);
        3) the device is still a tracked device, but it is disconnected (no attachment points).
        */
        if (numberOfDevices == 0 || numberOfDevices > 1 || attachedSwitches.isEmpty())
            return null;

        return attachedSwitches;
    }

    private Route getShortestPath(DatapathId startSwitch, Set<SwitchPort> endSwitches) {
        Route shortestPath = null;

        for (SwitchPort endSwitch : endSwitches) {
            Route candidateShortestPath = routingService.getRoute(startSwitch, OFPort.of(1),
                                                                  endSwitch.getSwitchDPID(), endSwitch.getPort(),
                                                                  U64.of(0));
            if (candidateShortestPath == null)
                continue;

            if (shortestPath == null) {
                shortestPath = candidateShortestPath;
                continue;
            }

            if (candidateShortestPath.compareTo(shortestPath) < 0)
                shortestPath = candidateShortestPath;
        }

        return shortestPath;
    }

    private Match.Builder createMatchWhenResponseFromServer(IOFSwitch sw, Ethernet ethernetFrame, IPv4 ipPacket) {
        MacAddress serverMAC = ethernetFrame.getSourceMACAddress();
        IPv4Address serverIP = ipPacket.getSourceAddress();
        MacAddress userMAC = ethernetFrame.getDestinationMACAddress();
        IPv4Address userIP = ipPacket.getDestinationAddress();
        Match.Builder matchBuilder = sw.getOFFactory().buildMatch();

        matchBuilder.setExact(MatchField.ETH_TYPE, EthType.IPv4)
                .setExact(MatchField.ETH_SRC, serverMAC)
                .setExact(MatchField.IPV4_SRC, serverIP)
                .setExact(MatchField.ETH_DST, userMAC)
                .setExact(MatchField.IPV4_DST, userIP);

        return matchBuilder;
    }

    private ArrayList<OFAction> translateSourceAddressToVirtual(IOFSwitch sw, OFPort outputPort) {
        OFOxms oxmsBuilder = sw.getOFFactory().oxms();
        OFActions actionBuilder = sw.getOFFactory().actions();
        ArrayList<OFAction> actionList = new ArrayList<>();

        OFActionSetField setMACSource = actionBuilder.buildSetField()
                .setField(oxmsBuilder.buildEthSrc().setValue(SERVICE_MAC).build())
                .build();

        OFActionSetField setIPSource = actionBuilder.buildSetField()
                .setField(oxmsBuilder.buildIpv4Src().setValue(SERVICE_IP).build())
                .build();

        OFActionOutput output = actionBuilder.buildOutput()
                .setMaxLen(0xFFffFFff)
                .setPort(outputPort)
                .build();

        actionList.add(setMACSource);
        actionList.add(setIPSource);
        actionList.add(output);

        return actionList;
    }

    private void instructSwitchWhenResponseFromServer(IOFSwitch sw, OFPacketIn packetIn, Ethernet ethernetFrame,
                                                      IPv4 ipPacket, OFPort outputPort) {
        /* Create a flow mod to:
           1) translate the server address (source address) to the virtual address of the service;
           2) forward the packet to the user (sw is an access switch).
        */
        OFFlowAdd.Builder flowModBuilder = sw.getOFFactory().buildFlowAdd();
        Match.Builder matchBuilder = createMatchWhenResponseFromServer(sw, ethernetFrame, ipPacket);
        ArrayList<OFAction> actionList = translateSourceAddressToVirtual(sw, outputPort);

        flowModBuilder.setIdleTimeout(IDLE_TIMEOUT);
        flowModBuilder.setHardTimeout(HARD_TIMEOUT);
        flowModBuilder.setBufferId(OFBufferId.NO_BUFFER);
        flowModBuilder.setOutPort(OFPort.ANY);
        flowModBuilder.setCookie(U64.of(0));
        flowModBuilder.setPriority(FlowModUtils.PRIORITY_MAX);
        flowModBuilder.setMatch(matchBuilder.build());
        flowModBuilder.setActions(actionList);

        sw.write(flowModBuilder.build());

        /* Create a packet-out doing the same actions specified in the flow mod, so that
        the packet arrived to the controller is delivered correctly and not dropped.
        */
        OFPacketOut.Builder packetOutBuilder = sw.getOFFactory().buildPacketOut();
        packetOutBuilder.setBufferId(packetIn.getBufferId());
        packetOutBuilder.setInPort(OFPort.ANY);
        packetOutBuilder.setActions(actionList);

        // If the packet-in encapsulates the original packet, the packet is sent back.
        if (packetIn.getBufferId() == OFBufferId.NO_BUFFER)
            packetOutBuilder.setData(packetIn.getData());

        sw.write(packetOutBuilder.build());
    }

    private void handleResponseFromServer(IOFSwitch sw, OFPacketIn packetIn, Ethernet ethernetFrame, IPv4 ipPacket) {
        MacAddress userMAC = ethernetFrame.getDestinationMACAddress();

        Set<SwitchPort> attachedSwitches = getSwitchesAttachedToDevice(userMAC);
        if (attachedSwitches == null) {
            logger.info("The user is not connected to the network. Dropping the packet.");
            return;
        }

        OFPort outputPort = null;
        for (SwitchPort attachedSwitch : attachedSwitches) {
            if (attachedSwitch.getSwitchDPID().equals(sw.getId())) {
                outputPort = attachedSwitch.getPort();
                break;
            }
        }

        if (outputPort == null) {
            logger.info("The user is not connected anymore to this access switch. Dropping the packet.");
            return;
        }
        logger.info("Output port towards the user: " + outputPort);

        instructSwitchWhenResponseFromServer(sw, packetIn, ethernetFrame, ipPacket, outputPort);
        logger.info("Packet-out and flow mod correctly sent to the switch.");
    }

    private ArrayList<OFAction> translateDestinationAddressToPhysical(IOFSwitch sw, MacAddress serverMAC,
                                                                      IPv4Address serverIP, OFPort outputPort) {
        OFOxms oxmsBuilder = sw.getOFFactory().oxms();
        OFActions actionBuilder = sw.getOFFactory().actions();
        ArrayList<OFAction> actionList = new ArrayList<>();

        OFActionSetField setMACDestination = actionBuilder.buildSetField()
                .setField(oxmsBuilder.buildEthDst().setValue(serverMAC).build())
                .build();

        OFActionSetField setIPDestination = actionBuilder.buildSetField()
                .setField(oxmsBuilder.buildIpv4Dst().setValue(serverIP).build())
                .build();

        OFActionOutput output = actionBuilder.buildOutput()
                .setMaxLen(0xFFffFFff)
                .setPort(outputPort)
                .build();

        actionList.add(setMACDestination);
        actionList.add(setIPDestination);
        actionList.add(output);

        return actionList;
    }

    private Match.Builder createMatchWhenRequestToService(IOFSwitch sw, Ethernet ethernetFrame, IPv4 ipPacket) {
        MacAddress userMAC = ethernetFrame.getSourceMACAddress();
        IPv4Address userIP = ipPacket.getSourceAddress();
        Match.Builder matchBuilder = sw.getOFFactory().buildMatch();

        matchBuilder.setExact(MatchField.ETH_TYPE, EthType.IPv4)
                .setExact(MatchField.ETH_SRC, userMAC)
                .setExact(MatchField.IPV4_SRC, userIP)
                .setExact(MatchField.ETH_DST, SERVICE_MAC)
                .setExact(MatchField.IPV4_DST, SERVICE_IP);

        return matchBuilder;
    }

    private void instructSwitchWhenRequestToService(IOFSwitch sw, OFPacketIn packetIn, Ethernet ethernetFrame,
                                                    IPv4 ipPacket, MacAddress serverMAC, IPv4Address serverIP,
                                                    OFPort outputPort) {
        /* Create a flow mod to:
           1) translate the virtual address of the service (destination address) to the
              address of the closest server;
           2) forward the packet towards the shortest path to the server itself.
        */
        OFFlowAdd.Builder flowModBuilder = sw.getOFFactory().buildFlowAdd();
        Match.Builder matchBuilder = createMatchWhenRequestToService(sw, ethernetFrame, ipPacket);
        ArrayList<OFAction> actionList = translateDestinationAddressToPhysical(sw, serverMAC, serverIP, outputPort);

        flowModBuilder.setIdleTimeout(IDLE_TIMEOUT);
        flowModBuilder.setHardTimeout(HARD_TIMEOUT);
        flowModBuilder.setBufferId(OFBufferId.NO_BUFFER);
        flowModBuilder.setOutPort(OFPort.ANY);
        flowModBuilder.setCookie(U64.of(0));
        flowModBuilder.setPriority(FlowModUtils.PRIORITY_MAX);
        flowModBuilder.setMatch(matchBuilder.build());
        flowModBuilder.setActions(actionList);

        sw.write(flowModBuilder.build());

        /* Create a packet-out doing the same actions specified in the flow mod, so that
        the packet arrived to the controller is delivered correctly and not dropped.
        */
        OFPacketOut.Builder packetOutBuilder = sw.getOFFactory().buildPacketOut();
        packetOutBuilder.setBufferId(packetIn.getBufferId());
        packetOutBuilder.setInPort(OFPort.ANY);
        packetOutBuilder.setActions(actionList);

        // If the packet-in encapsulates the original packet, the packet is sent back.
        if (packetIn.getBufferId() == OFBufferId.NO_BUFFER)
            packetOutBuilder.setData(packetIn.getData());

        sw.write(packetOutBuilder.build());
    }

    private void handleRequestToService(IOFSwitch sw, OFPacketIn packetIn, Ethernet ethernetFrame, IPv4 ipPacket) {
        MobilityServer closestServer = null;
        Route shortestPath = null;

        for (MobilityServer candidateClosestServer : servers) {

            Set<SwitchPort> attachedSwitches = getSwitchesAttachedToDevice(candidateClosestServer.getServerMAC());
            if (attachedSwitches == null)
                continue;

            // Compute the shortest path from the switch that sent the packet-in to the candidate server.
            Route candidateShortestPath = getShortestPath(sw.getId(), attachedSwitches);
            if (candidateShortestPath == null)
                continue;

            if (closestServer == null || candidateShortestPath.compareTo(shortestPath) < 0) {
                closestServer = candidateClosestServer;
                shortestPath = candidateShortestPath;
            }
            else if (candidateShortestPath.compareTo(shortestPath) == 0 &&
                     closestServer.hasMoreTranslations(candidateClosestServer)) {
                // Load balance the translation between servers.
                closestServer = candidateClosestServer;
                shortestPath = candidateShortestPath;
            }
        }

        if (closestServer == null) {
            logger.info("No server offering the service is available or reachable. Dropping the packet.");
            return;
        }

        // The output port of the current switch is specified by the second element of the path.
        OFPort outputPort = shortestPath.getPath().get(1).getPortId();
        closestServer.incrementTranslations();

        logger.debug("Path towards " + closestServer); // TODO: remove
        for (NodePortTuple pathNode : shortestPath.getPath()) //TODO: remove
            logger.debug("Node: " + pathNode.getNodeId() + " Port: " + pathNode.getPortId()); // TODO: remove

        logger.info("Chosen server for the translation: " + closestServer);
        logger.info("Output port towards the shortest path: " + outputPort);

        instructSwitchWhenRequestToService(sw, packetIn, ethernetFrame, ipPacket,
                                           closestServer.getServerMAC(),
                                           closestServer.getServerIP(),
                                           outputPort);
        logger.info("Packet-out and flow mod correctly sent to the switch.");
    }

    private Command handleIpPacket(IOFSwitch sw, OFPacketIn packetIn, Ethernet ethernetFrame, IPv4 ipPacket) {
        MacAddress sourceMAC = ethernetFrame.getSourceMACAddress();
        MacAddress destinationMAC = ethernetFrame.getDestinationMACAddress();
        IPv4Address sourceIP = ipPacket.getSourceAddress();
        IPv4Address destinationIP = ipPacket.getDestinationAddress();

        logger.info("Processing an IP packet.");
        logger.info("Switch: " + sw.getId());
        logger.info("Source: " + sourceMAC + ", " + sourceIP);
        logger.info("Destination: " + destinationMAC + ", " + destinationIP);

        // The packet is a request to the service from a user.
        if (isAccessSwitch(sw.getId()) && isServiceAddress(destinationMAC, destinationIP)) {
            logger.info("The packet is a request to the service transiting through an access switch.");
            logger.info("Handling the translation of the destination address.");
            handleRequestToService(sw, packetIn, ethernetFrame, ipPacket);
            return Command.STOP;
        }

        // The packet is a response from the service to a user.
        if (isAccessSwitch(sw.getId()) && isServerAddress(sourceMAC, sourceIP)) {
            logger.info("The packet is a response from the service transiting through an access switch.");
            logger.info("Handling the translation of the source address.");
            handleResponseFromServer(sw, packetIn, ethernetFrame, ipPacket);
            return Command.STOP;
        }

        // The packet is transiting through the network.
        logger.info("The packet is transiting through the network.");
        logger.info("Leaving the processing to the Forwarding module.");
        return Command.CONTINUE;
    }

    private IPacket createArpReplyForDevice(Ethernet ethernetFrame, ARP arpRequest, MacAddress deviceMac) {
        // Generate an ARP reply with source MAC address equal to deviceMac.
        return new Ethernet()
                .setSourceMACAddress(deviceMac)
                .setDestinationMACAddress(ethernetFrame.getSourceMACAddress())
                .setEtherType(EthType.ARP)
                .setPriorityCode(ethernetFrame.getPriorityCode())
                .setPayload(
                        new ARP()
                                .setHardwareType(ARP.HW_TYPE_ETHERNET)
                                .setProtocolType(ARP.PROTO_TYPE_IP)
                                .setHardwareAddressLength((byte) 6)
                                .setProtocolAddressLength((byte) 4)
                                .setOpCode(ARP.OP_REPLY)
                                .setSenderHardwareAddress(deviceMac)
                                .setSenderProtocolAddress(arpRequest.getTargetProtocolAddress())
                                .setTargetHardwareAddress(arpRequest.getSenderHardwareAddress())
                                .setTargetProtocolAddress(arpRequest.getSenderProtocolAddress()));
    }

    private IPacket createArpReplyForService(Ethernet ethernetFrame, ARP arpRequest) {
        // Generate an ARP reply with MAC address equal to SERVICE_MAC.
        return new Ethernet()
                .setSourceMACAddress(SERVICE_MAC)
                .setDestinationMACAddress(ethernetFrame.getSourceMACAddress())
                .setEtherType(EthType.ARP)
                .setPriorityCode(ethernetFrame.getPriorityCode())
                .setPayload(
                        new ARP()
                                .setHardwareType(ARP.HW_TYPE_ETHERNET)
                                .setProtocolType(ARP.PROTO_TYPE_IP)
                                .setHardwareAddressLength((byte) 6)
                                .setProtocolAddressLength((byte) 4)
                                .setOpCode(ARP.OP_REPLY)
                                .setSenderHardwareAddress(SERVICE_MAC)
                                .setSenderProtocolAddress(SERVICE_IP)
                                .setTargetHardwareAddress(arpRequest.getSenderHardwareAddress())
                                .setTargetProtocolAddress(arpRequest.getSenderProtocolAddress()));
    }

    private Command handleArpRequest(IOFSwitch sw, OFPacketIn packetIn, Ethernet ethernetFrame, ARP arpRequest) {
        IPacket arpReply = null;

        if(arpRequest.getTargetProtocolAddress().compareTo(SERVICE_IP) == 0 ){
            // The ARP request is issued to discover the virtual MAC of the service.
            arpReply = createArpReplyForService(ethernetFrame, arpRequest);
        } else {
            // The ARP request is issued by a server to discover the MAC address of a user or of another server.
            int numberOfDevices = 0;
            Iterator<? extends IDevice> devices = deviceService.queryDevices(null,
                                                                             null,
                                                                             arpRequest.getTargetProtocolAddress(),
                                                                             null,
                                                                             null);
            while (devices.hasNext()) {
                arpReply = createArpReplyForDevice(ethernetFrame, arpRequest, devices.next().getMACAddress());
                numberOfDevices++;

                if (numberOfDevices > 1) {
                    logger.error("Multiple devices with the same IP address were found in the network. " +
                                         "Dropping the ARP reply.");
                    return Command.STOP;
                }
            }

            if (arpReply == null) {
                logger.info("The IP address in the ARP request does not belong to a device in the network. " +
                                    "Dropping the ARP reply.");
                return Command.STOP;
            }
        }

        // Create the packet-out.
        OFPacketOut.Builder packetOutBuilder = sw.getOFFactory().buildPacketOut();
        packetOutBuilder.setBufferId(OFBufferId.NO_BUFFER);
        packetOutBuilder.setInPort(OFPort.ANY);

        // Create action: send the packet back from the source port.
        OFActionOutput.Builder actionBuilder = sw.getOFFactory().actions().buildOutput();
        OFPort inPort = packetIn.getMatch().get(MatchField.IN_PORT);
        actionBuilder.setPort(inPort);

        // Assign the action
        packetOutBuilder.setActions(Collections.singletonList((OFAction) actionBuilder.build()));

        // Set the ARP reply as packet data
        packetOutBuilder.setData(arpReply.serialize());

        logger.info("Sending out the ARP reply");
        sw.write(packetOutBuilder.build());

        return Command.STOP;
    }

    private boolean dropPacket(IOFSwitch sw, Ethernet ethernetFrame) {
        MacAddress sourceMAC = ethernetFrame.getSourceMACAddress();
        MacAddress destinationMAC = ethernetFrame.getDestinationMACAddress();
        logger.info("Received a packet from " + sourceMAC + " with destination " + destinationMAC);

        // If the packet comes from a server, it is always accepted.
        if (isServerAddress(sourceMAC, null)) {
            logger.info("The packet comes from a server. Accepting the packet.");
            return false;
        }

        // If the packet comes from an unsubscribed user, it is dropped.
        if (!isSubscribedUser(sourceMAC)) {
            logger.info("The packet comes from an unsubscribed user. Dropping the packet.");
            return true;
        }

        /* If the packet is coming from a subscribed user and it is transiting through the network,
        it passed a previous filtering done by an access switch.
        */
        if (!isAccessSwitch(sw.getId())) {
            logger.info("The packet comes from a subscribed user and it is " +
                                "transiting through the network. Accepting the packet.");
            return false;
        }

        // The packet is coming from a subscribed user and it is transiting through an access switch.
        IPacket packet = ethernetFrame.getPayload();

        // If the packet is an ARP request, it is allowed only if it targets the virtual IP.
        if ((ethernetFrame.isBroadcast() || ethernetFrame.isMulticast()) && packet instanceof ARP) {
            ARP arpRequest = (ARP) packet;

            if (arpRequest.getTargetProtocolAddress().compareTo(SERVICE_IP) != 0) {
                logger.info("The packet is an ARP request coming from the client and not addressed " +
                                    "to the service. Dropping the packet.");
                return true;
            }

            logger.info("The packet is an ARP request coming from the client and addressed " +
                                "to the service. Accepting the packet.");
            return false;
        }

        // If the packet is an IP request, check if IP or MAC destination addresses are virtual.
        if (packet instanceof IPv4) {
            IPv4 ipPacket = (IPv4) packet;

            if (!isServiceAddress(destinationMAC, ipPacket.getDestinationAddress())) {
                logger.info("The packet is an IP request coming from the client and not addressed " +
                                    "to the service. Dropping the packet.");
                return true;
            }

            logger.info("The packet is an IP request coming from the client and addressed " +
                                "to the service. Accepting the packet.");
            return false;
        }

        logger.info("The packet is neither an ARP request nor an IP packet. Dropping the packet.");
        return true;
    }

    @Override
    public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
        logger.debug("Entering receive()"); // TODO:remove

        // TODO: move inside "insertAccessSwitch" when REST interfaces is ready.
        for (DatapathId accessSwitch : accessSwitches)
            increasePriorityOfDefaultRule(accessSwitch);

        OFPacketIn packetIn = (OFPacketIn) msg;
        Ethernet ethernetFrame = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
        IPacket packet = ethernetFrame.getPayload();

        if (dropPacket(sw, ethernetFrame))
            return Command.STOP;

        if (packet instanceof ARP) {
            ARP arpRequest = (ARP) packet;
            logger.debug("ARP request"); // TODO: remove/rewrite
            return handleArpRequest(sw, packetIn, ethernetFrame, arpRequest);
        }

        if (packet instanceof IPv4) {
            IPv4 ipPacket = (IPv4) packet;
            logger.debug("IP request"); // TODO: remove/rewrite
            return handleIpPacket(sw, packetIn, ethernetFrame, ipPacket);
        }

        logger.debug("Skipped"); // TODO:remove
        return Command.STOP;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleServices() {
        return null;
    }

    @Override
    public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
        return null;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
        Collection<Class<? extends IFloodlightService>> dependencies = new ArrayList<>();

        dependencies.add(IFloodlightProviderService.class);
        dependencies.add(IOFSwitchService.class);
        dependencies.add(IDeviceService.class);
        dependencies.add(IRoutingService.class);

        return dependencies;
    }

    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        logger.info("Initializing mobility support module.");
        logger.info("Default service address: " + SERVICE_MAC + ", " + SERVICE_IP);
        logger.info("Using an idle/hard timeout of " + IDLE_TIMEOUT + "/" + HARD_TIMEOUT + " seconds.");
        logger.info("The priority of a default rule within an access switch is " + ACCESS_SWITCH_DEFAULT_RULE_PRIORITY);

        floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
        routingService = context.getServiceImpl(IRoutingService.class);
        deviceService = context.getServiceImpl(IDeviceService.class);
        switchService = context.getServiceImpl(IOFSwitchService.class);

        // TODO: remove and let the values be initialized by the REST interface.
        MobilityServer server1 = new MobilityServer(MacAddress.of("00:00:00:00:01:01"),
                                                    IPv4Address.of("10.0.1.1"));

        MobilityServer server2 = new MobilityServer(MacAddress.of("00:00:00:00:01:02"),
                                                    IPv4Address.of("10.0.1.2"));

        MobilityServer server3 = new MobilityServer(MacAddress.of("00:00:00:00:01:03"),
                                                    IPv4Address.of("10.0.1.3"));

        servers.add(server1);
        servers.add(server2);
        servers.add(server3);

        accessSwitches.add(DatapathId.of("00:00:00:00:00:00:00:01"));
        accessSwitches.add(DatapathId.of("00:00:00:00:00:00:00:03"));
        accessSwitches.add(DatapathId.of("00:00:00:00:00:00:00:05"));

        subscribedUsers.add(new MobilityUser("antonio", MacAddress.of("00:00:00:00:00:01")));
        subscribedUsers.add(new MobilityUser("giuseppe", MacAddress.of("00:00:00:00:00:02")));
        subscribedUsers.add(new MobilityUser("john doe", MacAddress.of("00:00:00:00:00:03")));
    }

    @Override
    public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
    }
}
