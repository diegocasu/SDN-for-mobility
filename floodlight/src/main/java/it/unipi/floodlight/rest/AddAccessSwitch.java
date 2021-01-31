package it.unipi.floodlight.rest;

import java.io.IOException;

import org.projectfloodlight.openflow.types.DatapathId;
import org.restlet.resource.Post;
import org.restlet.resource.ServerResource;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class AddAccessSwitch extends ServerResource{
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
			
			// Get the field dpid
			DatapathId dpid;
			try{
				dpid=DatapathId.of(root.get("dpid").asText());
			}catch(Exception me){
				return new String("Invalid DPID format");
			}
			
			IMobilitySupportREST ms = (IMobilitySupportREST) getContext().getAttributes().get(IMobilitySupportREST.class.getCanonicalName());
			result=ms.addAccessSwitch(dpid);
			
		} catch (IOException e) {
			e.printStackTrace();
			return new String("Error");
		}
		return result;
	}
}
