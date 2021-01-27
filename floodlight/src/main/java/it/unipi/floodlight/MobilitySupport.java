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
    private MacAddress SERVICE_MAC = MacAddress.of("FE:FE:FE:FE:FE:FE");

    // Subscribed users.
    private Map<String, MacAddress> subscribedUsers = new HashMap<>();

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
    	return Command.CONTINUE;
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
        
        subscribedUsers.put("aaaa",MacAddress.of("00:00:00:00:00:01"));
        subscribedUsers.put("bbbb",MacAddress.of("00:00:00:00:00:02"));
        subscribedUsers.put("cccc",MacAddress.of("00:00:00:00:00:03"));

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
	        // This resource will insert a given user
	        router.attach("/insertuser/json", InsertUser.class);
	        // This resource will remove a given user
	        router.attach("/removeuser/json", RemoveUser.class);
	        // This resource will show Server Virtual IP and MAC Address
	        router.attach("/getserveraddress/json", GetVirtualAddress.class);
	        // This resource will set Server Virtual IP and MAC Address
	        router.attach("/setserveraddress/json", SetVirtualAddress.class);
	        // This resource will show the list of servers providing the service
	        router.attach("/getservers/json", GetServers.class);
	        // This resource will show the list of servers providing the service
	        router.attach("/addserver/json", AddServer.class);
    		
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
    public Map<String, Object> getSubscribedUsers(){
    	Map<String, Object> list = new HashMap<String, Object>();
    	
		for (Map.Entry me : subscribedUsers.entrySet()){
	    	list.put((String)me.getKey(),me.getValue().toString());
	    }
	
		return list;
    }
    
    @Override
    public String subscribeUser(String username, MacAddress MAC){
    	//check if user is already subscribed or if the username is already present.
    	for (Map.Entry me : subscribedUsers.entrySet()){
    		if(((MacAddress)me.getValue()).toString().equals(MAC.toString()))
    			return new String("User already subscribed");
    		if(((String)me.getKey()).equals(username))
    			return new String("Username already in use");
	    }
    	//insert new user
    	subscribedUsers.put(username,MAC);
    	
    	return "Subscription Successful";
    }
    
    @Override
    public String removeUser(String username){
    	//check if the user is subscribed
    	for (Map.Entry me : subscribedUsers.entrySet()){
    		if(((String)me.getKey()).equals(username)){
    			subscribedUsers.remove(username);
    			return new String("User Removed");
    		}		
	    }
    	return new String("Username not present");
    }
    
    @Override
    public Map<String, Object> getVirtualAddress(){
    	Map<String, Object> info = new HashMap<String, Object>();
    	
		info.put("MAC:", SERVICE_MAC.toString());
		info.put("IPv4:", SERVICE_IP.toString());
		
		return info;
    }
    
    @Override
    public String setVirtualAddress(IPv4Address ipv4, MacAddress MAC){
    	//update virtual address
    	SERVICE_IP=ipv4;
    	SERVICE_MAC=MAC;
    	
    	return "Virtual Address Updated";
    }
    
    @Override
    public Map<String, Object> getServers(){
    	Map<String, Object> list = new HashMap<String, Object>();
    	
		for (Map.Entry me : server.entrySet()){
	    	list.put(me.getKey().toString(),me.getValue().toString());
	    }
	
		return list;
    } 
    
    @Override
    public String addServer(IPv4Address ipv4, MacAddress MAC){
    	//check if server is already present.
    	for (Map.Entry me : server.entrySet()){
    		if(((MacAddress)me.getValue()).toString().equals(MAC.toString()))
    			return new String("MAC Address Already Present");
    		if(((IPv4Address)me.getKey()).toString().equals(ipv4.toString()))
    			return new String("IPv4 Already Present");
	    }
    	//insert new user
    	server.put(ipv4,MAC);
    	
    	return "Server Added";
    }
}