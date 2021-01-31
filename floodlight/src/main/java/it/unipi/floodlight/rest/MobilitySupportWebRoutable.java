package it.unipi.floodlight.rest;

import net.floodlightcontroller.restserver.RestletRoutable;
import org.restlet.Context;
import org.restlet.Restlet;
import org.restlet.routing.Router;

/**
 * Class to define the REST interface
 */

public class MobilitySupportWebRoutable implements RestletRoutable {
    /**
     * Create the Restlet router and bind to the proper resources.
     */
    @Override
    public Restlet getRestlet(Context context) {

        Router router = new Router(context);

        /**
         * This resource will manage the subscribedUsers Map.
         * @GET 	permit to retrieve the list of subscribed users
         * @POST 	permit to insert a given user
         * 			@JSON:	"username","MAC"
         * @DELETE	permit to remove a given user
         * 			@JSON:	"username"
         */
        router.attach("/users/json", Users.class);
        
        // This resource will show Server Virtual IP and MAC Address
        router.attach("/getserveraddress/json", GetVirtualAddress.class);
        // This resource will set Server Virtual IP and MAC Address
        // Json parameters: "ipv4","MAC"
        router.attach("/setserveraddress/json", SetVirtualAddress.class);
        // This resource will show the list of servers providing the service
        router.attach("/getservers/json", GetServers.class);
        // This resource will add a given server to the list of available servers
        // Json parameters: "ipv4","MAC"
        router.attach("/addserver/json", AddServer.class);
        // This resource will remove a given server to the list of available servers
        // Json parameters: "ipv4"
        router.attach("/removeserver/json", RemoveServer.class);
        // This resource will show the list of access switches
        router.attach("/getaccessswitches/json", GetAccessSwitches.class);
        // This resource will add a given switch to the list of access switches
        // Json parameters: "dpid"
        router.attach("/addaccessswitch/json", AddAccessSwitch.class);
        // This resource will add a given switch to the list of access switches
        // Json parameters: "dpid"
        router.attach("/removeaccessswitch/json", RemoveAccessSwitch.class);

        return router;
    }

    /**
     * Set the base path.
     */
    @Override
    public String basePath() {
        return "/ms";
    }
}