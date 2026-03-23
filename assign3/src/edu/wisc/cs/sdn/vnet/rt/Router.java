package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
	private ArpCache arpCache;
	
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
	}
	
	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable()
	{ return this.routeTable; }
	
	/**
	 * Load a new routing table from a file.
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile)
	{
		if (!routeTable.load(routeTableFile, this))
		{
			System.err.println("Error setting up routing table from file "
					+ routeTableFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}
	
	/**
	 * Load a new ARP cache from a file.
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile)
	{
		if (!arpCache.load(arpCacheFile))
		{
			System.err.println("Error setting up ARP cache from file "
					+ arpCacheFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * 
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface     the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface) {
		System.out.println("*** -> Received packet: " +
				etherPacket.toString().replace("\n", "\n\t"));

		// this router only forwards ipv4
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4) {
			return;
		}

		IPv4 ipPacket = (IPv4) etherPacket.getPayload();

		// validate the incoming ip header checksum before forwarding
		short receivedChecksum = ipPacket.getChecksum();
		ipPacket.setChecksum((short) 0);
		ipPacket.serialize();
		short computedChecksum = ipPacket.getChecksum();
		ipPacket.setChecksum(receivedChecksum);
		if (receivedChecksum != computedChecksum) {
			return;
		}

		// ttl must stay positive after decrement
		int ttl = ipPacket.getTtl() & 0xff;
		if (ttl <= 1) {
			return;
		}
		ipPacket.setTtl((byte) (ttl - 1));
		ipPacket.resetChecksum();
		ipPacket.serialize();

		// do not forward packets addressed to a router interface
		int dstIp = ipPacket.getDestinationAddress();
		for (Iface iface : this.interfaces.values()) {
			if (iface.getIpAddress() == dstIp) {
				return;
			}
		}

		// longest-prefix route lookup
		RouteEntry bestMatch = this.routeTable.lookup(dstIp);
		if (bestMatch == null) {
			return;
		}

		Iface outIface = bestMatch.getInterface();
		if (outIface == null) {
			return;
		}
		if (outIface.getMacAddress() == null) {
			return;
		}

		// resolve next-hop mac from static arp cache
		int nextHopIp = bestMatch.getGatewayAddress();
		if (nextHopIp == 0) {
			nextHopIp = dstIp;
		}

		ArpEntry arpEntry = this.arpCache.lookup(nextHopIp);
		if (arpEntry == null) {
			return;
		}

		// rewrite ethernet header for the outgoing hop, then transmit
		etherPacket.setSourceMACAddress(outIface.getMacAddress().toBytes());
		etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());
		this.sendPacket(etherPacket, outIface);
	}
}
