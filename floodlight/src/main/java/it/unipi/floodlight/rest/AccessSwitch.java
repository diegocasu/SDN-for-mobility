package it.unipi.floodlight.rest;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.projectfloodlight.openflow.types.DatapathId;
import org.restlet.resource.Delete;
import org.restlet.resource.Get;
import org.restlet.resource.Post;
import org.restlet.resource.ServerResource;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class AccessSwitch extends ServerResource {

	@Get("json")
    public Set<String> show() {
    	IMobilitySupportREST ms = (IMobilitySupportREST) getContext().getAttributes().get(IMobilitySupportREST.class.getCanonicalName());
    	return ms.getAccessSwitches();
    }

	@Post("json")
	public Map<String, String> store(String fmJson) {
		Map<String, String> result = new HashMap<>();
		
        // Check if the payload is provided
		if (fmJson == null) {
			result.put("message", "No parameters provided");
			return result;
		}

		// Parse the JSON input
		ObjectMapper mapper = new ObjectMapper();
		try {
			JsonNode root = mapper.readTree(fmJson);
			
			/* Get the field dpid.
			DatapathId.of() does not check if the dpid is well-formed,
			but addAccessSwitch() checks if it belongs to a connected switch.
			*/
			DatapathId dpid = DatapathId.of(root.get("dpid").asText());

			IMobilitySupportREST ms = (IMobilitySupportREST) getContext().getAttributes().get(IMobilitySupportREST.class.getCanonicalName());
			result.put("message", ms.addAccessSwitch(dpid));

		} catch (IOException e) {
			e.printStackTrace();
			result.put("message", "An exception occurred while parsing the parameters");
		}

		return result;
	}

	@Delete("json")
	public Map<String, String> remove(String fmJson) {
		Map<String, String> result = new HashMap<>();

		// Check if the payload is provided
		if (fmJson == null) {
			result.put("message", "No parameters provided");
			return result;
		}

		// Parse the JSON input
		ObjectMapper mapper = new ObjectMapper();
		try {
			JsonNode root = mapper.readTree(fmJson);
			
			/* Get the field dpid.
			DatapathId.of() does not check if the dpid is well-formed,
			but removeAccessSwitch() checks if it belongs to a connected switch.
			*/
			DatapathId dpid = DatapathId.of(root.get("dpid").asText());

			IMobilitySupportREST ms = (IMobilitySupportREST) getContext().getAttributes().get(IMobilitySupportREST.class.getCanonicalName());
			result.put("message", ms.removeAccessSwitch(dpid));

		} catch (IOException e) {
			e.printStackTrace();
			result.put("message", "An exception occurred while parsing the parameters");
		}

		return result;
	}
}
