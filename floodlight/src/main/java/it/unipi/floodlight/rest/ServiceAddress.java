package it.unipi.floodlight.rest;

import java.io.IOException;
import java.util.Map;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;
import org.restlet.resource.Get;
import org.restlet.resource.Post;
import org.restlet.resource.ServerResource;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class ServiceAddress extends ServerResource{
	@Get("json")
    public Map<String, Object> show() {
    	IMobilitySupportREST ms = (IMobilitySupportREST) getContext().getAttributes().get(IMobilitySupportREST.class.getCanonicalName());
    	return ms.getVirtualAddress();
    }
	@Post("json")
	public String store(String fmJson) {
		String result = new String();
		
        // Check if the payload is provided
        if(fmJson == null){
            return new String("No parameters");
        }
		// Parse the JSON input
		ObjectMapper mapper = new ObjectMapper();
		try {
			
			JsonNode root = mapper.readTree(fmJson);
			
			// Get the field ipv4
			IPv4Address ipv4;
			try{
				ipv4=IPv4Address.of(root.get("ipv4").asText());
			}catch(Exception me){
				return new String("Invalid IPv4 Address format");
			}
			// Get the field MAC
			MacAddress MAC;
			try{
				MAC=MacAddress.of(root.get("MAC").asText());
			}catch(Exception me){
				return new String("Invalid MAC Address format");
			}
			
			IMobilitySupportREST ms = (IMobilitySupportREST) getContext().getAttributes().get(IMobilitySupportREST.class.getCanonicalName());
			result=ms.setVirtualAddress(ipv4, MAC);
			
		} catch (IOException e) {
			e.printStackTrace();
			return new String("Error");
		}
		return result;
	}
}
