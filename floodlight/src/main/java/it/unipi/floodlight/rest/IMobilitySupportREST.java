package it.unipi.floodlight.rest;

import java.util.Map;
import java.util.Set;

import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;
import net.floodlightcontroller.core.module.IFloodlightService;


/**
 * Interface defining the methods that must be implemented to realize the REST interface.
 */
public interface IMobilitySupportREST extends IFloodlightService {

	/**
	 * Retrieves the list of subscribed users.
	 * @return  the list of subscribed users, identified by their MAC addresses and usernames.
	 */
	Map<String, Object> getSubscribedUsers();

	/**
	 * Adds a user to the list of subscribed ones.
	 * @param username  the username of the user.
	 * @param MAC       the MAC address of the user.
	 * @return          a message carrying information about the success of the operation.
	 */
	String subscribeUser(String username, MacAddress MAC);

	/**
	 * Removes a user from the list of subscribed ones.
	 * @param username  the username of the user.
	 * @return          a message carrying information about the success of the operation.
	 */
	String removeUser(String username);

	/**
	 * Retrieves the virtual MAC and IP addresses of the service.
	 * @return  the virtual MAC and IP addresses of the service.
	 */
	Map<String, Object> getVirtualAddress();

	/**
	 * Changes the virtual MAC and IP addresses of the service.
	 * @param ipv4  the new IPv4 address of the service.
	 * @param MAC   the new MAC address of the service.
	 * @return      a message carrying information about the success of the operation.
	 */
	String setVirtualAddress(IPv4Address ipv4, MacAddress MAC);

	/**
	 * Retrieves the list of servers implementing the service.
	 * @return  the list of servers, identified by their MAC addresses and the IPv4 addresses.
	 */
	Map<String, Object> getServers();

	/**
	 * Adds a server to the list of servers implementing the service.
	 * @param ipv4  the IPv4 address of the server.
	 * @param MAC   the MAC address of the server.
	 * @return      a message carrying information about the success of the operation.
	 */
	String addServer(IPv4Address ipv4, MacAddress MAC);

	/**
	 * Removes a server from the list of servers implementing the service.
	 * @param ipv4  the IPv4 address of the server.
	 * @return      a message carrying information about the success of the operation.
	 */
	String removeServer(IPv4Address ipv4);

	/**
	 * Retrieves the list of access switches.
	 * @return  the list of access switches, identified by their DPIDs.
	 */
	Set<String> getAccessSwitches();

	/**
	 * Adds a switch to the list of access switches.
	 * @param dpid  the DPID of the switch.
	 * @return      a message carrying information about the success of the operation.
	 */
	String addAccessSwitch(DatapathId dpid);

	/**
	 * Removes a switch from the list of access switches.
	 * @param dpid  the DPID of the switch.
	 * @return      a message carrying information about the success of the operation.
	 */
	String removeAccessSwitch(DatapathId dpid);
}
