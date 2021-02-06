package it.unipi.floodlight.rest;

import net.floodlightcontroller.restserver.RestletRoutable;
import org.restlet.Context;
import org.restlet.Restlet;
import org.restlet.routing.Router;


/**
 * Class defining the REST interface of the MobilitySupport module.
 */
public class MobilitySupportWebRoutable implements RestletRoutable {

    /**
     * Creates the Restlet router and binds it to the proper resources.
     * @param context the context for constructing the restlet.
     * @return        the Restlet router.
     */
    @Override
    public Restlet getRestlet(Context context) {
        Router router = new Router(context);

        /*
         * This resource will manage the list of subscribed users.
         * @GET 	permits to retrieve the list of subscribed users.
         * @POST 	permits to insert a given user.
         * 			@JSON:	"username","mac"
         * @DELETE	permits to remove a given user.
         * 			@JSON:	"username"
         */
        router.attach("/users/json", User.class);
        
        /*
         * This resource will manage the service MAC and IP addresses.
         * @GET 	permits to get IPv4 and MAC addresses of the service.
         * @POST 	permits to insert IPv4 and MAC addresses of the service.
         * 			@JSON:	"ipv4","mac"
         */
        router.attach("/service-address/json", ServiceAddress.class);
        
        /*
         * This resource will manage the list of servers.
         * @GET 	permits to retrieve the list of servers providing the service.
         * @POST 	permits to insert a given server.
         * 			@JSON:	"ipv4","mac"
         * @DELETE	permits to remove a given server.
         * 			@JSON:	"ipv4"
         */
        router.attach("/servers/json", Server.class);
        
        /*
         * This resource will manage the list of access switches.
         * @GET 	permits to retrieve the list of access switches.
         * @POST 	permits to insert a given access switch.
         * 			@JSON:	"dpid"
         * @DELETE	permits to remove a given access switch.
         * 			@JSON:	"dpid"
         */
        router.attach("/access-switches/json", AccessSwitch.class);
        
        return router;
    }

    /**
     * Sets the base path for the endpoints of the REST interface.
     * @return  the base path.
     */
    @Override
    public String basePath() {
        return "/ms";
    }
}