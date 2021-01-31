package it.unipi.floodlight.rest;

import java.util.Map;

import org.restlet.resource.Get;
import org.restlet.resource.ServerResource;

public class GetUserList extends ServerResource{
	@Get("json")
    public Map<String, Object> show() {	
    	IMobilitySupportREST ms = (IMobilitySupportREST) getContext().getAttributes().get(IMobilitySupportREST.class.getCanonicalName());
    	return ms.getSubscribedUsers();	
    }
}