package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.RIPv2;
import net.floodlightcontroller.packet.RIPv2Entry;
import net.floodlightcontroller.packet.UDP;

import java.util.Timer;
import java.util.TimerTask;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	/** RIP multicast destination IP address */
	private static final int RIP_MULTICAST_IP = IPv4.toIPv4Address("224.0.0.9");

	/** Broadcast destination MAC address used for RIP request/response flooding */
	private static final String RIP_BROADCAST_MAC = "FF:FF:FF:FF:FF:FF";

	/** Period for unsolicited RIP responses */
	private static final long RIP_PERIOD_MS = 10_000L;

	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
	private ArpCache arpCache;

	/** Whether RIP mode is enabled */
	private boolean ripEnabled;

	/** Periodic task timer for unsolicited RIP responses */
	private Timer ripResponseTimer;
	// TODO: add learned-route metadata storage keyed by destination+mask (metric, nextHop, lastUpdateMs, isDirect) for RIP DV
	
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
		this.ripResponseTimer = null;
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
		this.startPeriodicRIPResponses();
		// TODO: start a periodic timeout sweep that expires learned (non-direct) routes not refreshed for >30s
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
	 * Begin periodic unsolicited RIP responses every 10 seconds.
	 */
	private void startPeriodicRIPResponses()
	{
		if (this.ripResponseTimer != null)
		{ return; }

		this.ripResponseTimer = new Timer(true);
		this.ripResponseTimer.scheduleAtFixedRate(new TimerTask()
		{
			@Override
			public void run()
			{ sendUnsolicitedRIPResponses(); }
		}, RIP_PERIOD_MS, RIP_PERIOD_MS);
	}

	/**
	 * Determine whether an IP packet is a RIP packet.
	 * RIP packets are UDP packets with destination port 520.
	 */
	private boolean isRIPPacket(IPv4 ipPacket)
	{
		if (ipPacket.getProtocol() != IPv4.PROTOCOL_UDP)
		{ return false; }
		if (!(ipPacket.getPayload() instanceof UDP))
		{ return false; }

		UDP udpPacket = (UDP)ipPacket.getPayload();
		return (udpPacket.getDestinationPort() == UDP.RIP_PORT);
	}

	/**
	 * Handle a RIP packet that arrived on an interface.
	 */
	private void handleRIPPacket(Ethernet etherPacket, IPv4 ipPacket, Iface inIface)
	{
		if (!(ipPacket.getPayload() instanceof UDP))
		{ return; }

		UDP udpPacket = (UDP)ipPacket.getPayload();
		if (!(udpPacket.getPayload() instanceof RIPv2))
		{ return; }

		RIPv2 ripPacket = (RIPv2)udpPacket.getPayload();
		if (ripPacket.getCommand() == RIPv2.COMMAND_REQUEST)
		{
			// respond directly to the requesting router interface
			this.sendUnicastRIPResponse(inIface,
					ipPacket.getSourceAddress(),
					etherPacket.getSourceMACAddress());
		}
		else if (ripPacket.getCommand() == RIPv2.COMMAND_RESPONSE)
		{
			// TODO: process RIP response entries and update route table:
			// - candidateMetric=min(received+1,16)
			// - preserve direct routes
			// - add/replace/refresh learned routes by next hop
			// - treat metric 16 from current next hop as unreachable
		}
	}

	/**
	 * Send unsolicited RIP responses out all interfaces.
	 */
	private void sendUnsolicitedRIPResponses()
	{
		for (Iface iface : this.interfaces.values())
		{
			this.sendRIPResponse(iface, RIP_MULTICAST_IP,
					Ethernet.toMACAddress(RIP_BROADCAST_MAC));
		}
	}

	/**
	 * Send a unicast RIP response to one router interface.
	 */
	private void sendUnicastRIPResponse(Iface outIface, int destinationIp,
			byte[] destinationMac)
	{
		this.sendRIPResponse(outIface, destinationIp, destinationMac);
	}

	/**
	 * Build and send a RIP response packet through one interface.
	 */
	private void sendRIPResponse(Iface outIface, int destinationIp,
			byte[] destinationMac)
	{
		if (outIface.getMacAddress() == null || outIface.getIpAddress() == 0)
		{ return; }

		RIPv2 rip = new RIPv2();
		rip.setCommand(RIPv2.COMMAND_RESPONSE);
		this.addRIPResponseEntries(rip);

		UDP udp = new UDP();
		udp.setSourcePort(UDP.RIP_PORT);
		udp.setDestinationPort(UDP.RIP_PORT);
		udp.setPayload(rip);

		IPv4 ip = new IPv4();
		ip.setTtl((byte)64);
		ip.setSourceAddress(outIface.getIpAddress());
		ip.setDestinationAddress(destinationIp);
		ip.setPayload(udp);

		Ethernet ether = new Ethernet();
		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setSourceMACAddress(outIface.getMacAddress().toBytes());
		ether.setDestinationMACAddress(destinationMac);
		ether.setPayload(ip);

		this.sendPacket(ether, outIface);
	}

	/**
	 * Populate RIP response entries from currently directly connected subnets.
	 * Learned entries are added in a later checkpoint.
	 */
	private void addRIPResponseEntries(RIPv2 rip)
	{
		// TODO: include learned routes in advertisements using stored RIP metrics (not only directly connected subnets)
		for (Iface iface : this.interfaces.values())
		{
			if ((iface.getIpAddress() == 0) || (iface.getSubnetMask() == 0))
			{ continue; }

			int subnet = iface.getIpAddress() & iface.getSubnetMask();
			RIPv2Entry entry = new RIPv2Entry(subnet, iface.getSubnetMask(), 1);
			rip.addEntry(entry);
		}
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

		// RIP traffic is handled locally (not via normal forwarding path)
		if (this.ripEnabled && this.isRIPPacket(ipPacket))
		{
			this.handleRIPPacket(etherPacket, ipPacket, inIface);
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

	// TODO: override destroy() to cancel RIP timers/tasks cleanly before calling super.destroy()
}
