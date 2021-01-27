package it.unipi.floodlight;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.restserver.IRestApiService;
import net.floodlightcontroller.restserver.RestletRoutable;

import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;
import org.restlet.Context;
import org.restlet.Restlet;
import org.restlet.routing.Router;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;


public class MobilitySupport implements IFloodlightModule, IOFMessageListener, IMobilitySupportREST {
    protected static Logger logger = LoggerFactory.getLogger(MobilitySupport.class);
    protected IFloodlightProviderService floodlightProvider;
    protected IRestApiService restApiService; // Reference to the Rest API service

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
        return false;
    }

    @Override
    public boolean isCallbackOrderingPostreq(OFType type, String name) {
        return false;
    }

    @Override
    public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
        return null;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleServices() {
    	Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
	    l.add(IMobilitySupportREST.class);
	    return l;
    }

    @Override
    public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
    	Map<Class<? extends IFloodlightService>, IFloodlightService> m = new HashMap<Class<? extends IFloodlightService>, IFloodlightService>();
	    m.put(IMobilitySupportREST.class, this);
	    return m;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
        Collection<Class<? extends IFloodlightService>> dependency = new ArrayList<>();
        dependency.add(IFloodlightProviderService.class);

        // Add among the dependences the RestApi service
	    dependency.add(IRestApiService.class);
        return dependency;
    }

    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        logger.info("Initializing mobility support module.");
        floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
        // Retrieve a pointer to the rest api service
     	restApiService = context.getServiceImpl(IRestApiService.class);

        server.put(IPv4Address.of("10.0.1.1"), MacAddress.of("00:00:00:00:01:01"));
        server.put(IPv4Address.of("10.0.1.2"), MacAddress.of("00:00:00:00:01:02"));
        server.put(IPv4Address.of("10.0.1.3"), MacAddress.of("00:00:00:00:01:03"));
        
        subscribedUser.put("aaaa",MacAddress.of("00:00:00:00:00:01"));
        subscribedUser.put("bbbb",MacAddress.of("00:00:00:00:00:02"));
        subscribedUser.put("cccc",MacAddress.of("00:00:00:00:00:03"));

        accessSwitch.add(DatapathId.of("00:00:00:00:00:00:AC:01"));
        accessSwitch.add(DatapathId.of("00:00:00:00:00:00:AC:03"));
        accessSwitch.add(DatapathId.of("00:00:00:00:00:00:AC:02"));
    }

    @Override
    public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
        
        // Add as REST interface the one defined in the LoadBalancerWebRoutable class
     	restApiService.addRestletRoutable(new MobilitySupportWebRoutable());
    }
    
    /**
	 * Class to define the rest interface 
	 */
    
    public class MobilitySupportWebRoutable implements RestletRoutable {
	    /**
	     * Create the Restlet router and bind to the proper resources.
	     */
    	@Override
		public Restlet getRestlet(Context context) {
			
    		Router router = new Router(context);
    		
    		// This resource will show the list of subscribed users
	        router.attach("/getusers/json", GetUserList.class);
    		
			return router;
		}
	 
	    /**
	     * Set the base path for the Topology
	     */
	    @Override
	    public String basePath() {
	        return "/ms";
	    }
	}
    
    @Override
    public Map<String, MacAddress> getSubscribedUser(){
    	return subscribedUser;
    }
    
    @Override
    public boolean subscribeUser(String username, MacAddress MAC){
    	return true;
    }
    
    @Override
    public boolean removeUser(String username){
    	return true;
    }
    
}