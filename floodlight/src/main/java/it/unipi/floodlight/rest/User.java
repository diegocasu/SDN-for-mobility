package it.unipi.floodlight.rest;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.projectfloodlight.openflow.types.MacAddress;
import org.restlet.resource.Delete;
import org.restlet.resource.Get;
import org.restlet.resource.Post;
import org.restlet.resource.ServerResource;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;


/**
 * Class managing the resource "/users/json".
 */
public class User extends ServerResource {

	/**
	 * Retrieves the list of subscribed users.
	 * @return  the list of subscribed users.
	 */
	@Get("json")
    public Map<String, Object> show() {	
    	IMobilitySupportREST ms = (IMobilitySupportREST) getContext().getAttributes().get(IMobilitySupportREST.class.getCanonicalName());
    	return ms.getSubscribedUsers();
    }

	/**
	 * Subscribes a user to the service.
	 * @param fmJson  the JSON message.
	 * @return        a message carrying information about the success of the operation.
	 */
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
			
			// Get the field username
			String username = root.get("username").asText();

			// Get the field MAC
			MacAddress MAC;
			try {
				MAC = MacAddress.of(root.get("mac").asText());
			} catch (IllegalArgumentException e) {
				result.put("message", "Invalid MAC address format");
				return result;
			}
			
			IMobilitySupportREST ms = (IMobilitySupportREST) getContext().getAttributes().get(IMobilitySupportREST.class.getCanonicalName());
			result.put("message", ms.subscribeUser(username, MAC));
			
		} catch (IOException e) {
			e.printStackTrace();
			result.put("message", "An exception occurred while parsing the parameters");
		}

		return result;
	}

	/**
	 * Removes a user from the list of subscribed ones.
	 * @param fmJson  the JSON message.
	 * @return        a message carrying information about the success of the operation.
	 */
	@Delete("json")
	public Map<String, String> remove(String fmJson) {
		Map<String, String> result = new HashMap<>();
		
        // Check if the payload is provided
        if(fmJson == null){
			result.put("message", "No parameters provided");
			return result;
        }

		// Parse the JSON input
		ObjectMapper mapper = new ObjectMapper();
		try {
			JsonNode root = mapper.readTree(fmJson);
			
			// Get the field username
			String username = root.get("username").asText();
			
			IMobilitySupportREST ms = (IMobilitySupportREST) getContext().getAttributes().get(IMobilitySupportREST.class.getCanonicalName());
			result.put("message", ms.removeUser(username));
			
		} catch (IOException e) {
			e.printStackTrace();
			result.put("message", "An exception occurred while parsing the parameters");
		}

		return result;
	}
}
