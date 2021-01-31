package it.unipi.floodlight.rest;

import java.io.IOException;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.restlet.resource.Delete;
import org.restlet.resource.ServerResource;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class RemoveServer extends ServerResource{
	@Delete("json")
	public String remove(String fmJson) {
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
			
			IMobilitySupportREST ms = (IMobilitySupportREST) getContext().getAttributes().get(IMobilitySupportREST.class.getCanonicalName());
			result=ms.removeServer(ipv4);
			
		} catch (IOException e) {
			e.printStackTrace();
			return new String("Error");
		}
		return result;
	}
}
