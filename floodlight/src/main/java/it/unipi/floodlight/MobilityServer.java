package it.unipi.floodlight;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;

import java.math.BigInteger;
import java.util.Objects;


public class MobilityServer {
    private final MacAddress serverMAC;
    private final IPv4Address serverIP;
    private BigInteger numberOfTranslations;


    public MobilityServer(MacAddress serverMAC, IPv4Address serverIP) {
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
        return serverMAC.equals(that.getServerMAC()) && serverIP.equals(that.getServerIP());
    }

    @Override
    public int hashCode() {
        return Objects.hash(serverMAC, serverIP);
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
