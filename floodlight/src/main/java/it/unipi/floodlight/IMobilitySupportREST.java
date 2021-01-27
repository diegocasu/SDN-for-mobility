package it.unipi.floodlight;

import java.util.Map;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;
import net.floodlightcontroller.core.module.IFloodlightService;

//Service interface for the module
//This interface will be use to interact with other modules
//Export here all the methods of the class that are likely used by other modules

public interface IMobilitySupportREST extends IFloodlightService{
	//It returns the list of subscribed users
	public Map<String, Object> getSubscribedUsers();
	
	//It subscribe a given user to the service.
	public String subscribeUser(String username, MacAddress MAC);
	
	//It remove a given user from the list of subscribed users. It returns true if removal was successful
	public String removeUser(String username);
	
	//It returns the server Virtual IP and MAC
	public Map<String, Object> getVirtualAddress();
	
	//It subscribe a given user to the service.
	public String setVirtualAddress(IPv4Address ipv4, MacAddress MAC);
	
	//It show the list of servers
	public Map<String, Object> getServers();
	
	//It subscribe a given user to the service.
	public String addServer(IPv4Address ipv4, MacAddress MAC);
}
