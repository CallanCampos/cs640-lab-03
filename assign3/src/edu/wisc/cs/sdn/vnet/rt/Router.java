package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.RIPv2;
import net.floodlightcontroller.packet.UDP;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	/** RIP multicast destination IP address */
	private static final int RIP_MULTICAST_IP = IPv4.toIPv4Address("224.0.0.9");

	/** Broadcast destination MAC address used for RIP request/response flooding */
	private static final String RIP_BROADCAST_MAC = "FF:FF:FF:FF:FF:FF";

	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
	private ArpCache arpCache;

	/** Whether RIP mode is enabled */
	private boolean ripEnabled;
	
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
		this.ripEnabled = false;
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
	 * Start RIP mode for the router.
	 * Adds directly connected subnet routes and sends an initial RIP request
	 * out all interfaces.
	 */
	public void startRIP()
	{
		if (this.ripEnabled)
		{ return; }
		this.ripEnabled = true;
		this.addDirectlyConnectedRoutes();
		this.sendInitialRIPRequests();
	}

	/**
	 * Add routes for all subnets directly connected to this router's interfaces.
	 * Each direct route has no gateway (0.0.0.0).
	 */
	private void addDirectlyConnectedRoutes()
	{
		for (Iface iface : this.interfaces.values())
		{
			if ((iface.getIpAddress() == 0) || (iface.getSubnetMask() == 0))
			{ continue; }

			int subnet = iface.getIpAddress() & iface.getSubnetMask();
			this.routeTable.insert(subnet, 0, iface.getSubnetMask(), iface);
		}

		System.out.println("Initialized directly connected routes for RIP");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}

	/**
	 * Send one RIP request out each interface.
	 */
	private void sendInitialRIPRequests()
	{
		for (Iface iface : this.interfaces.values())
		{ this.sendRIPRequest(iface); }
	}

	/**
	 * Build and transmit a RIP request on one interface.
	 * Request packets are sent to RIP multicast IP and Ethernet broadcast MAC.
	 */
	private void sendRIPRequest(Iface outIface)
	{
		if (outIface.getMacAddress() == null || outIface.getIpAddress() == 0)
		{ return; }

		RIPv2 rip = new RIPv2();
		rip.setCommand(RIPv2.COMMAND_REQUEST);

		UDP udp = new UDP();
		udp.setSourcePort(UDP.RIP_PORT);
		udp.setDestinationPort(UDP.RIP_PORT);
		udp.setPayload(rip);

		IPv4 ip = new IPv4();
		ip.setTtl((byte) 64);
		ip.setSourceAddress(outIface.getIpAddress());
		ip.setDestinationAddress(RIP_MULTICAST_IP);
		ip.setPayload(udp);

		Ethernet ether = new Ethernet();
		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setSourceMACAddress(outIface.getMacAddress().toBytes());
		ether.setDestinationMACAddress(RIP_BROADCAST_MAC);
		ether.setPayload(ip);

		this.sendPacket(ether, outIface);
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
		// never route a packet back out the interface it arrived on
		if (outIface == inIface) {
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
