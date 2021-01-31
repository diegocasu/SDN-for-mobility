package it.unipi.floodlight.rest;

import java.io.IOException;

import org.projectfloodlight.openflow.types.MacAddress;
import org.restlet.resource.Post;
import org.restlet.resource.ServerResource;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class InsertUser extends ServerResource{
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
			
			// Get the field username
			String username = root.get("username").asText();
			// Get the field MAC
			MacAddress MAC;
			try{
				MAC=MacAddress.of(root.get("MAC").asText());
			}catch(Exception me){
				return new String("Invalid MAC Address format");
			}
			
			IMobilitySupportREST ms = (IMobilitySupportREST) getContext().getAttributes().get(IMobilitySupportREST.class.getCanonicalName());
			result=ms.subscribeUser(username, MAC);
			
		} catch (IOException e) {
			e.printStackTrace();
			return new String("Error");
		}
		return result;
	}
}
