package it.unipi.floodlight.rest;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;
import org.restlet.resource.Get;
import org.restlet.resource.Post;
import org.restlet.resource.ServerResource;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;


/**
 * Class managing the resource "/service-address/json".
 */
public class ServiceAddress extends ServerResource {

	/**
	 * Retrieves the MAC and IPv4 addresses of the service.
	 * @return  the MAC and IPv4 addresses of the service.
	 */
	@Get("json")
    public Map<String, Object> show() {
    	IMobilitySupportREST ms = (IMobilitySupportREST) getContext().getAttributes().get(IMobilitySupportREST.class.getCanonicalName());
    	return ms.getVirtualAddress();
    }

	/**
	 * Modifies the MAC and IPv4 addresses of the service.
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
			
			// Get the field ipv4
			IPv4Address ipv4;
			try {
				ipv4 = IPv4Address.of(root.get("ipv4").asText());
			} catch (IllegalArgumentException e) {
				result.put("message", "Invalid IPv4 Address format");
				return result;
			}

			// Get the field MAC
			MacAddress MAC;
			try {
				MAC = MacAddress.of(root.get("mac").asText());
			} catch (IllegalArgumentException e) {
				result.put("message", "Invalid MAC address format");
				return result;
			}
			
			IMobilitySupportREST ms = (IMobilitySupportREST) getContext().getAttributes().get(IMobilitySupportREST.class.getCanonicalName());
			result.put("message", ms.setVirtualAddress(ipv4, MAC));

		} catch (IOException e) {
			e.printStackTrace();
			result.put("message", "An exception occurred while parsing the parameters");
		}

		return result;
	}
}
