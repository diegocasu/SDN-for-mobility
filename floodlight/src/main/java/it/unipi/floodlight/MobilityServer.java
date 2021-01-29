package it.unipi.floodlight;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;

import java.math.BigInteger;


public class MobilityServer {
    private final MacAddress serverMAC;
    private final IPv4Address serverIP;
    private BigInteger numberOfTranslations;


    public MobilityServer(MacAddress serverMAC, IPv4Address serverIP) {
        if (serverMAC == null)
            throw new IllegalArgumentException("The MAC address of the server must be specified.");

        // The IP address can be null, to allow comparisons when only the MAC address is known.
        this.serverIP = serverIP;
        this.serverMAC = serverMAC;
        this.numberOfTranslations = new BigInteger("0");
    }

    public IPv4Address getServerIP() {
        return serverIP;
    }

    public MacAddress getServerMAC() {
        return serverMAC;
    }

    public BigInteger getNumberOfTranslations() {
        return numberOfTranslations;
    }

    public void incrementTranslations() {
        numberOfTranslations = numberOfTranslations.add(BigInteger.ONE);
    }

    public boolean hasMoreTranslations(MobilityServer that) {
        return (numberOfTranslations.compareTo(that.getNumberOfTranslations()) > 0);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;

        if (o == null || getClass() != o.getClass())
            return false;

        MobilityServer that = (MobilityServer) o;

        // If one of the IP addresses is null, compare only the MAC addresses.
        if (serverIP == null || that.getServerIP() == null)
            return serverMAC.equals(that.getServerMAC());

        return serverMAC.equals(that.getServerMAC()) && serverIP.equals(that.getServerIP());
    }

    @Override
    public int hashCode() {
        /* Use only the MAC address, which is unique, to have a consistent hashCode()
        behaviour with respect to equals() when the IP address is null.
        */
        return serverMAC.hashCode();
    }

    @Override
    public String toString() {
        return "MobilityServer{" +
                "serverMAC=" + serverMAC +
                ", serverIP=" + serverIP +
                ", numberOfTranslations=" + numberOfTranslations +
                '}';
    }
}
