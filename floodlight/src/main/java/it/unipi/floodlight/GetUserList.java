package it.unipi.floodlight;

import java.util.Map;

import org.projectfloodlight.openflow.types.MacAddress;
import org.restlet.resource.Get;
import org.restlet.resource.ServerResource;

public class GetUserList extends ServerResource{
	
	@Get("json")
    public Map<String, MacAddress> Test() {
    	
    	IMobilitySupportREST ms = (IMobilitySupportREST) getContext().getAttributes().get(IMobilitySupportREST.class.getCanonicalName());
    	return ms.getSubscribedUser();
    	
    }

}