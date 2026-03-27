package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.RIPv2;
import net.floodlightcontroller.packet.RIPv2Entry;
import net.floodlightcontroller.packet.UDP;

import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	private static class LearnedRoute {
		//dest address and subnet mask
		private int destinationAddress;
		private int subnetMask;

		private int metric;
		private long lastUpdate;
		private int nextHopAddress;
		private boolean directRoute;

	}

	/** RIP multicast destination IP address */
	private static final int RIP_MULTICAST_IP = IPv4.toIPv4Address("224.0.0.9");

	/** Broadcast destination MAC address used for RIP request/response flooding */
	private static final String RIP_BROADCAST_MAC = "FF:FF:FF:FF:FF:FF";

	/** Period for unsolicited RIP responses */
	private static final long RIP_PERIOD_MS = 10_000L;

	/** Period for route timeout in milliseconds */
	private static final long ROUTE_TIMEOUT_MS = 30_000L;

	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
	private ArpCache arpCache;

	/** Whether RIP mode is enabled */
	private boolean ripEnabled;

	/** Periodic task timer for unsolicited RIP responses */
	private Timer ripResponseTimer;

	
	/** Map of learned routes keyed by destination+mask */
	private Map<String, LearnedRoute> learnedRoutes;

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
		this.learnedRoutes = new ConcurrentHashMap<String, LearnedRoute>();
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

			int ipAddress = iface.getIpAddress();
			int subnetMask = iface.getSubnetMask();
			
			int subnet = ipAddress & subnetMask;

			this.routeTable.insert(subnet, 0, iface.getSubnetMask(), iface);
			//add to learned routes
			String key = this.routeKey(subnet, subnetMask);
			this.learnedRoutes.put(key, createLearnedRoute(subnet, subnetMask,
					1, 0, true));
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
		ip.setProtocol(IPv4.PROTOCOL_UDP);
		

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
			//inface goes to ourface and source mac goes to dest mac
			this.sendRIPResponse(inIface,
					ipPacket.getSourceAddress(),
					etherPacket.getSourceMACAddress());
		}
		//take in info of the response 
		else if (ripPacket.getCommand() == RIPv2.COMMAND_RESPONSE)
		{
			this.expireStaleLearnedRoutes();
			int nextHopIp = ipPacket.getSourceAddress();
			for (RIPv2Entry entry : ripPacket.getEntries())
			{ this.applyRIPResponseEntry(entry, nextHopIp, inIface); }
		}
	}

	/**
	 * Apply one RIP response entry using basic distance-vector behavior.
	 */
	private void applyRIPResponseEntry(RIPv2Entry entry, int nextHopIp, Iface inIface)
	{
		int subnetMask = entry.getSubnetMask();
		int destinationSubnet = entry.getAddress() & subnetMask;
		int candidateMetric = Math.min(entry.getMetric() + 1, 16);
		String key = this.routeKey(destinationSubnet, subnetMask);

		LearnedRoute current = this.learnedRoutes.get(key);

		// Never replace or remove directly connected routes.
		if ((current != null) && current.directRoute)
		{ return; }

		// Unreachable route: remove only if we currently use this next hop.
		if (candidateMetric >= 16)
		{
			if ((current != null) && (current.nextHopAddress == nextHopIp))
			{
				this.learnedRoutes.remove(key);
				this.routeTable.remove(destinationSubnet, subnetMask);
			}
			return;
		}

		// New learned route.
		if (current == null)
		{
			LearnedRoute route = createLearnedRoute(destinationSubnet, subnetMask,
					candidateMetric, nextHopIp, false);
			this.learnedRoutes.put(key, route);
			this.routeTable.insert(destinationSubnet, nextHopIp, subnetMask, inIface);
			return;
		}

		// Refresh route from its current next hop (even if metric changes).
		if (current.nextHopAddress == nextHopIp)
		{
			current.metric = candidateMetric;
			current.lastUpdate = System.currentTimeMillis();
			if (!this.routeTable.update(destinationSubnet, subnetMask, nextHopIp, inIface))
			{ this.routeTable.insert(destinationSubnet, nextHopIp, subnetMask, inIface); }
			return;
		}

		// Better path from different next hop.
		if (candidateMetric < current.metric)
		{
			current.metric = candidateMetric;
			current.lastUpdate = System.currentTimeMillis();
			current.nextHopAddress = nextHopIp;
			if (!this.routeTable.update(destinationSubnet, subnetMask, nextHopIp, inIface))
			{ this.routeTable.insert(destinationSubnet, nextHopIp, subnetMask, inIface); }
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
		ip.setProtocol(IPv4.PROTOCOL_UDP);

		Ethernet ether = new Ethernet();
		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setSourceMACAddress(outIface.getMacAddress().toBytes());
		ether.setDestinationMACAddress(destinationMac);
		ether.setPayload(ip);

		this.sendPacket(ether, outIface);
	}

	/**
	 * Populate RIP response entries from currently learned routes.
	 */
	private void addRIPResponseEntries(RIPv2 rip)
	{
		this.expireStaleLearnedRoutes();
		//loop through learned routes and attach all of them
		//dont need to attach nexthop as if someone uses our route, OUR interface is thier next hop
		for(LearnedRoute route : this.learnedRoutes.values()) {
			RIPv2Entry entry = new RIPv2Entry(route.destinationAddress, route.subnetMask, route.metric);
			rip.addEntry(entry);
		}

	}

	/**
	 * Remove learned routes that have not been refreshed in over 30 seconds.
	 */
	private void expireStaleLearnedRoutes()
	{
		long now = System.currentTimeMillis();
		for (Map.Entry<String, LearnedRoute> entry : this.learnedRoutes.entrySet())
		{
			LearnedRoute route = entry.getValue();
			if (route.directRoute)
			{ continue; }
			if ((now - route.lastUpdate) <= ROUTE_TIMEOUT_MS)
			{ continue; }

			if (this.learnedRoutes.remove(entry.getKey(), route))
			{ this.routeTable.remove(route.destinationAddress, route.subnetMask); }
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
		// enforce 30s expiration
		if (this.ripEnabled)
		{ this.expireStaleLearnedRoutes(); }
		
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

	private String routeKey(int destAddr, int subnetMask)
	{ return String.valueOf(destAddr) + "/" + String.valueOf(subnetMask); }

	private LearnedRoute createLearnedRoute(int destAddr, int subnetMask,
			int metric, int nextHopAddress, boolean directRoute){
		LearnedRoute route = new LearnedRoute();
		route.destinationAddress = destAddr;
		route.subnetMask = subnetMask;
		route.metric = metric;
		route.lastUpdate = System.currentTimeMillis();
		route.nextHopAddress = nextHopAddress;
		route.directRoute = directRoute;
		return route;

	}
	/**
	 * Cancel RIP timers/tasks cleanly before calling super.destroy()
	 */
	@Override
	public void destroy() {
		if (this.ripResponseTimer != null)
		{ this.ripResponseTimer.cancel(); }
		super.destroy();
	}

}
