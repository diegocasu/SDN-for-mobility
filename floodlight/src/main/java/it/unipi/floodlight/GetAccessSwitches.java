package it.unipi.floodlight;

import java.util.Map;
import java.util.Set;

import org.restlet.resource.Get;
import org.restlet.resource.ServerResource;

public class GetAccessSwitches extends ServerResource{
	@Get("json")
    public Set<String> show() {
    	IMobilitySupportREST ms = (IMobilitySupportREST) getContext().getAttributes().get(IMobilitySupportREST.class.getCanonicalName());
    	return ms.getAccessSwitches();
    }
}
