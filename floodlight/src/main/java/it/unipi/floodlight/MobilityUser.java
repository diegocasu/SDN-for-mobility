package it.unipi.floodlight;

import org.projectfloodlight.openflow.types.MacAddress;


public class MobilityUser {
    private final String username;
    private final MacAddress userMAC;


    public MobilityUser(String username, MacAddress userMAC) {
        if (userMAC == null)
            throw new IllegalArgumentException("The MAC address of the user must be specified.");

        // The username can be null, to allow comparisons when only the MAC address is known.
        this.username = username;
        this.userMAC = userMAC;
    }

    public String getUsername() {
        return username;
    }

    public MacAddress getUserMAC() {
        return userMAC;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;

        if (o == null || getClass() != o.getClass())
            return false;

        MobilityUser that = (MobilityUser) o;

        // If one of the usernames is null, compare only the MAC addresses.
        if (username == null || that.getUsername() == null)
            return userMAC.equals(that.getUserMAC());

        return username.equals(that.getUsername()) && userMAC.equals(that.getUserMAC());
    }

    @Override
    public int hashCode() {
        /* Use only the MAC address, which is unique, to have a consistent hashCode()
        behaviour with respect to equals() when the username is null.
        */
        return userMAC.hashCode();
    }

    @Override
    public String toString() {
        return "MobilityUser{" +
                "username='" + username + '\'' +
                ", userMAC=" + userMAC +
                '}';
    }
}
