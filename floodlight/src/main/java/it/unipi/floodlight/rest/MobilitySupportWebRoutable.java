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
         * @GET 	permits to retrieve the list of subscribed users
         * @POST 	permits to insert a given user
         * 			@JSON:	"username","MAC"
         * @DELETE	permits to remove a given user
         * 			@JSON:	"username"
         */
        router.attach("/users/json", User.class);
        
        /**
         * This resource will manage the SERVICE_IP IPv4Address and SERVICE_MAC MacAddress.
         * @GET 	permits to get IPv4 and MAC of the service
         * @POST 	permits to insert IPv4 and MAC of the service
         * 			@JSON:	"ipv4","MAC"
         */
        router.attach("/service-address/json", ServiceAddress.class);
        
        /**
         * This resource will manage the servers Map.
         * @GET 	permits to retrieve the list of servers providing the service
         * @POST 	permits to insert a given server
         * 			@JSON:	"ipv4","MAC"
         * @DELETE	permits to remove a given server
         * 			@JSON:	"ipv4"
         */
        router.attach("/servers/json", Server.class);
        
        /**
         * This resource will manage the accessSwitches Set.
         * @GET 	permits to retrieve the list of access switches
         * @POST 	permits to insert a given access switch
         * 			@JSON:	"dpid"
         * @DELETE	permits to remove a given access switch
         * 			@JSON:	"dpid"
         */
        router.attach("/access-switches/json", AccessSwitch.class);
        
        return router;
    }

    //Set the base path
    @Override
    public String basePath() {
        return "/ms";
    }
}