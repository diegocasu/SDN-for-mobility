package it.unipi.floodlight;

import java.util.Map;

import org.restlet.resource.Get;
import org.restlet.resource.ServerResource;

public class GetServers extends ServerResource{
	@Get("json")
    public Map<String, Object> show() {
    	IMobilitySupportREST ms = (IMobilitySupportREST) getContext().getAttributes().get(IMobilitySupportREST.class.getCanonicalName());
    	return ms.getServers();
    }
}
