package it.unipi.floodlight;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IListener.Command;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.internal.Device;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;

import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;


public class MobilitySupport implements IFloodlightModule, IOFMessageListener {
    protected static Logger logger = LoggerFactory.getLogger(MobilitySupport.class);
    protected IFloodlightProviderService floodlightProvider;
    protected IDeviceService device;

    // Default virtual IP and MAC addresses of the service.
    private IPv4Address SERVICE_IP = IPv4Address.of("8.8.8.8");
    private MacAddress SERVICE_MAC =  MacAddress.of("FE:FE:FE:FE:FE:FE");

    // Subscribed users.
    private Map<String, MacAddress> subscribedUser = new HashMap<>();

    // Servers implementing the service.
    private HashMap<IPv4Address, MacAddress> server = new HashMap<>();

    // Access switch.
    private Set<DatapathId> accessSwitch = new HashSet<>();


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

    @Override
    public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
                IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

        IPacket pkt = eth.getPayload();

        // Cast to Packet-In
        OFPacketIn pi = (OFPacketIn) msg;


        if(!server.containsValue(eth.getSourceMACAddress())){
            // This packet comes from a client (not a server)

            logger.info("--> This packet comes from a client. MAC: " + eth.getSourceMACAddress());
            if(subscribedUser.containsValue(eth.getSourceMACAddress())){
                // This packet comes from a subscribed user

                logger.info("---> This packet comes from a subscribed user ");
                if(accessSwitch.contains(sw.getId())){ // Potrebbe non essere necessario, perchè siccome
                    // The PACKET_IN comes from an access switch

                    logger.info("----> The PACKET_IN comes from an access switch ");
                    if(eth.isBroadcast() || eth.isMulticast()){
                        if (pkt instanceof ARP) {
                            // This is an ARP request from the client

                            logger.info("----->  This is an ARP request from the client ");
                            ARP ARPrequest= (ARP) eth.getPayload();

                            if(ARPrequest.getTargetProtocolAddress().compareTo(SERVICE_IP) != 0){
                                // The ARP request from the client has the wrong IP Target Address --> Discard the packet

                                logger.error("------>  The ARP request from the client has the wrong IP Target Address --> Discard the packet ");
                                return Command.STOP;

                            } else {
                                // The ARP request from the client has the correct (the virtual one) IP target Address --> Reply to the ARP Request

                                logger.info("------>  The ARP request from the client has the correct (the virtual one) IP target Address --> Reply to the ARP Request");

                                handleARPRequest(sw, pi, cntx);

                                return Command.CONTINUE;

                            }
                        }
                    } else {
                        // This is not an ARP request, check if it is an IP packet

                        logger.info("-----> This is not an ARP request, check if it is an IP packet");
                        if (pkt instanceof IPv4) {
                            // This is an IP packet, check if IP or MAC destination address are virtual

                            logger.info("------> This is an IP packet, check if IP or MAC destination address are virtual");
                            IPv4 IPpacket = (IPv4) eth.getPayload();
                            if((!(eth.getDestinationMACAddress().compareTo(SERVICE_MAC) == 0))
                                    || (!(IPpacket.getDestinationAddress().compareTo(SERVICE_IP) == 0))){
                                // The MAC or the IP address are not the virtual address of the service --> Discard the packet

                                logger.error("-------> The MAC or the IP address are not the virtual address of the service --> Discard the packet");
                                return Command.STOP;

                            } else {
                                // Both MAC and IP address are correct (virtual address of the service)

                                logger.info("-------> Both MAC and IP address are correct (virtual address of the service)");
                                return Command.STOP; //Just for testing, remove it
                            }
                        } else {
                            // This is neither an ARP request, nor an IP packet --> Discard the packet

                            logger.info("-----> This is neither an ARP request, nor an IP packet --> Discard the packet");
                            return Command.STOP;
                        }
                    }
                } else{
                    // The PACKET_IN comes from an internal switch (from a subscribed user)

                }

            } else {
                //This packet comes from an unsubscribed user

                logger.info("---> This packet comes from an unsubscribed user --> Discard the packet");
                return Command.STOP;
            }
        } else {
            // This Packet comes from a Server, filtering not needed, we accept everything from servers

            if(eth.isBroadcast() || eth.isMulticast()){
                if (pkt instanceof ARP) {
                    // This is an ARP request from the server
                    // Since the access switch for the server will reply to the ARP request of the server
                    // we are sure that there will be no broadcast ARP request entering internal switches
                    // so this is for sure an access switch for the server.

                    logger.info("----->  This is an ARP request from the server ");
                    ARP ARPrequest= (ARP) eth.getPayload();

                    handleARPRequest(sw, pi, cntx);

                    return Command.CONTINUE;

                }
            }

        }



        return Command.STOP;
    }

    private void handleARPRequest(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx) {

        // Double check that the payload is ARP
        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
        if (! (eth.getPayload() instanceof ARP))
            return;

        // Cast the ARP request
        ARP arpRequest = (ARP) eth.getPayload();

        if( arpRequest.getTargetProtocolAddress().compareTo(SERVICE_IP) == 0 ){
            //This ARP request is the one issued by the client to discover Server (Virtual) MAC

            // Generate ARP reply with MAC address = SERVICE_MAC
            IPacket arpReply = new Ethernet()
                    .setSourceMACAddress(SERVICE_MAC)
                    .setDestinationMACAddress(eth.getSourceMACAddress())
                    .setEtherType(EthType.ARP)
                    .setPriorityCode(eth.getPriorityCode())
                    .setPayload(
                            new ARP()
                                    .setHardwareType(ARP.HW_TYPE_ETHERNET)
                                    .setProtocolType(ARP.PROTO_TYPE_IP)
                                    .setHardwareAddressLength((byte) 6)
                                    .setProtocolAddressLength((byte) 4)
                                    .setOpCode(ARP.OP_REPLY)
                                    .setSenderHardwareAddress(SERVICE_MAC) // Set my MAC address
                                    .setSenderProtocolAddress(SERVICE_IP) // Set my IP address
                                    .setTargetHardwareAddress(arpRequest.getSenderHardwareAddress())
                                    .setTargetProtocolAddress(arpRequest.getSenderProtocolAddress()));

            // Create the Packet-Out and set basic data for it (buffer id and in port)
            OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
            pob.setBufferId(OFBufferId.NO_BUFFER);
            pob.setInPort(OFPort.ANY);

            // Create action -> send the packet back from the source port
            OFActionOutput.Builder actionBuilder = sw.getOFFactory().actions().buildOutput();
            OFPort inPort =  pi.getMatch().get(MatchField.IN_PORT);
            actionBuilder.setPort(inPort);

            // Assign the action
            pob.setActions(Collections.singletonList((OFAction) actionBuilder.build()));

            // Set the ARP reply as packet data
            byte[] packetData = arpReply.serialize();
            pob.setData(packetData);

            logger.info("-------> Sending out ARP reply to the client\n");

            sw.write(pob.build());
        } else {
            // This ARP request is the one issued by the server to discover the client MAC

            Iterator<? extends IDevice> devices = device.queryDevices(null, null, arpRequest.getTargetProtocolAddress(), null, null);

            if(devices.hasNext()){
                // It exists one device with the given IP

                MacAddress clientMAC = devices.next().getMACAddress();
                // Send the ARP response to the Server containing the MAC of the client

                // Generate ARP reply with MAC address = the MAC returned from the DeviceManager
                IPacket arpReply = new Ethernet()
                        .setSourceMACAddress(clientMAC)
                        .setDestinationMACAddress(eth.getSourceMACAddress())
                        .setEtherType(EthType.ARP)
                        .setPriorityCode(eth.getPriorityCode())
                        .setPayload(
                                new ARP()
                                        .setHardwareType(ARP.HW_TYPE_ETHERNET)
                                        .setProtocolType(ARP.PROTO_TYPE_IP)
                                        .setHardwareAddressLength((byte) 6)
                                        .setProtocolAddressLength((byte) 4)
                                        .setOpCode(ARP.OP_REPLY)
                                        .setSenderHardwareAddress(clientMAC) // Set client MAC address
                                        .setSenderProtocolAddress(arpRequest.getTargetProtocolAddress()) // Set client IP address
                                        .setTargetHardwareAddress(arpRequest.getSenderHardwareAddress())
                                        .setTargetProtocolAddress(arpRequest.getSenderProtocolAddress()));

                // Create the Packet-Out and set basic data for it (buffer id and in port)
                OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
                pob.setBufferId(OFBufferId.NO_BUFFER);
                pob.setInPort(OFPort.ANY);

                // Create action -> send the packet back from the source port
                OFActionOutput.Builder actionBuilder = sw.getOFFactory().actions().buildOutput();
                OFPort inPort =  pi.getMatch().get(MatchField.IN_PORT);
                actionBuilder.setPort(inPort);

                // Assign the action
                pob.setActions(Collections.singletonList((OFAction) actionBuilder.build()));

                // Set the ARP reply as packet data
                byte[] packetData = arpReply.serialize();
                pob.setData(packetData);

                logger.info("------->  Sending out ARP reply to the server\n");

                sw.write(pob.build());
            }

        }
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
        Collection<Class<? extends IFloodlightService>> dependency = new ArrayList<>();
        dependency.add(IFloodlightProviderService.class);
        dependency.add(IDeviceService.class);

        return dependency;
    }

    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        //logger.info("Initializing mobility support module.");
        floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
        device = context.getServiceImpl(IDeviceService.class);

        server.put(IPv4Address.of("10.0.1.1"), MacAddress.of("00:00:00:00:01:01"));
        server.put(IPv4Address.of("10.0.1.2"), MacAddress.of("00:00:00:00:01:02"));
        server.put(IPv4Address.of("10.0.1.3"), MacAddress.of("00:00:00:00:01:03"));

        accessSwitch.add(DatapathId.of("00:00:00:00:00:00:AC:01"));
        accessSwitch.add(DatapathId.of("00:00:00:00:00:00:AC:03"));
        accessSwitch.add(DatapathId.of("00:00:00:00:00:00:AC:02"));

        // added for test
        subscribedUser.put("antonio", MacAddress.of("00:00:00:00:00:01"));
        subscribedUser.put("giuseppe", MacAddress.of("00:00:00:00:00:04"));
    }

    @Override
    public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
    }
}
