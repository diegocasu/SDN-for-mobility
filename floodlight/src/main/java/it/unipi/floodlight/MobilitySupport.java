package it.unipi.floodlight;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;

import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;


public class MobilitySupport implements IFloodlightModule, IOFMessageListener {
    protected static Logger logger = LoggerFactory.getLogger(MobilitySupport.class);
    protected IFloodlightProviderService floodlightProvider;

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
        return null;
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

        return dependency;
    }

    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        logger.info("Initializing mobility support module.");
        floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);

        server.put(IPv4Address.of("10.0.1.1"), MacAddress.of("00:00:00:00:01:01"));
        server.put(IPv4Address.of("10.0.1.2"), MacAddress.of("00:00:00:00:01:02"));
        server.put(IPv4Address.of("10.0.1.3"), MacAddress.of("00:00:00:00:01:03"));

        accessSwitch.add(DatapathId.of("00:00:00:00:00:00:AC:01"));
        accessSwitch.add(DatapathId.of("00:00:00:00:00:00:AC:03"));
        accessSwitch.add(DatapathId.of("00:00:00:00:00:00:AC:02"));
    }

    @Override
    public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
    }
}
