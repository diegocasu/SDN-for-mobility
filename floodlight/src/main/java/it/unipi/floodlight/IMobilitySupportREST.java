package it.unipi.floodlight;

import java.util.Map;

import org.projectfloodlight.openflow.types.MacAddress;
import net.floodlightcontroller.core.module.IFloodlightService;

//Service interface for the module
//This interface will be use to interact with other modules
//Export here all the methods of the class that are likely used by other modules

public interface IMobilitySupportREST extends IFloodlightService{
	//It returns the list of subscribed users
	public Map<String, MacAddress> getSubscribedUser();
	
	//It subscribe a given user to the service. It returns true if subscription was successful
	public boolean subscribeUser(String username, MacAddress MAC);
	
	//It remove a given user from the list of subscribed users. It returns true if removal was successful
	public boolean removeUser(String username);
}
