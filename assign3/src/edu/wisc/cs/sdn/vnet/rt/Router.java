package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.RIPv2;
import net.floodlightcontroller.packet.RIPv2Entry;
import net.floodlightcontroller.packet.UDP;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;

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
		private boolean directRoute;
		private int gatewayAddress;
		private Iface iface;

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

	/** Synchronizes RIP route updates with periodic advertisements */
	private final Object ripLock;

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
		this.learnedRoutes = new HashMap<String, LearnedRoute>();
		this.ripLock = new Object();
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
				String key = this.getRouteKey(subnet, subnetMask);
				this.learnedRoutes.put(key,
						createLearnedRoute(subnet, subnetMask, 1, true, 0, iface));
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
			synchronized (this.ripLock)
			{
				long now = System.currentTimeMillis();
				this.pruneExpiredRoutesLocked(now);
				for (RIPv2Entry entry : ripPacket.getEntries())
				{
					this.updateRouteFromResponse(entry, ipPacket.getSourceAddress(),
							inIface, now);
				}
			}
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
		List<RIPv2Entry> responseEntries = new ArrayList<RIPv2Entry>();
		synchronized (this.ripLock)
		{
			this.pruneExpiredRoutesLocked(System.currentTimeMillis());
			for (LearnedRoute route : this.learnedRoutes.values())
			{
				responseEntries.add(new RIPv2Entry(route.destinationAddress,
						route.subnetMask, route.metric));
			}
		}
		for (RIPv2Entry entry : responseEntries)
		{ rip.addEntry(entry); }
	}

	private void pruneExpiredRoutes()
	{
		synchronized (this.ripLock)
		{ this.pruneExpiredRoutesLocked(System.currentTimeMillis()); }
	}

	private void pruneExpiredRoutesLocked(long now)
	{
		Iterator<Map.Entry<String, LearnedRoute>> iterator =
				this.learnedRoutes.entrySet().iterator();
		while (iterator.hasNext())
		{
			Map.Entry<String, LearnedRoute> mapEntry = iterator.next();
			LearnedRoute route = mapEntry.getValue();
			if (!this.isRouteExpired(route, now))
			{ continue; }

			iterator.remove();
			this.routeTable.remove(route.destinationAddress, route.subnetMask);
		}
	}

	private boolean isRouteExpired(LearnedRoute route, long now)
	{
		return (!route.directRoute
				&& (route.lastUpdate + ROUTE_TIMEOUT_MS < now));
	}

	private boolean isRouteUsable(RouteEntry routeEntry)
	{
		if (!this.ripEnabled)
		{ return true; }

		synchronized (this.ripLock)
		{
			String routeKey = this.getRouteKey(routeEntry.getDestinationAddress(),
					routeEntry.getMaskAddress());
			LearnedRoute route = this.learnedRoutes.get(routeKey);
			if (route == null)
			{ return false; }

			long now = System.currentTimeMillis();
			if (this.isRouteExpired(route, now))
			{
				this.learnedRoutes.remove(routeKey);
				this.routeTable.remove(route.destinationAddress, route.subnetMask);
				return false;
			}

			return (route.metric < 16);
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

		if (this.ripEnabled)
		{ this.pruneExpiredRoutes(); }
		
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

		if (!this.isRouteUsable(bestMatch)) {
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

	private LearnedRoute createLearnedRoute(int destAddr, int subnetMask, int metric,
			boolean directRoute, int gatewayAddress, Iface iface){
		LearnedRoute route = new LearnedRoute();
		route.destinationAddress = destAddr;
		route.subnetMask = subnetMask;
		route.metric = metric;
		route.lastUpdate = System.currentTimeMillis();
		route.directRoute = directRoute;
		route.gatewayAddress = gatewayAddress;
		route.iface = iface;
		return route;

	}

	private String getRouteKey(int destAddr, int subnetMask)
	{
		return String.valueOf(destAddr) + "/" + String.valueOf(subnetMask);
	}

	private int getLearnedMetric(int advertisedMetric)
	{
		return Math.min(16, advertisedMetric + 1);
	}

	private void updateRouteFromResponse(RIPv2Entry entry, int gatewayAddress,
			Iface inIface, long now)
	{
		int destAddr = entry.getAddress();
		int subnetMask = entry.getSubnetMask();
		int learnedMetric = this.getLearnedMetric(entry.getMetric());
		String routeKey = this.getRouteKey(destAddr, subnetMask);
		LearnedRoute learnedRoute = this.learnedRoutes.get(routeKey);

		if ((learnedRoute != null) && learnedRoute.directRoute)
		{ return; }

		if (learnedRoute == null)
		{
			if (learnedMetric >= 16)
			{ return; }

			this.learnedRoutes.put(routeKey,
					createLearnedRoute(destAddr, subnetMask, learnedMetric, false,
							gatewayAddress, inIface));
			this.routeTable.insert(destAddr, gatewayAddress, subnetMask, inIface);
			return;
		}

		boolean fromCurrentNextHop =
				(learnedRoute.gatewayAddress == gatewayAddress)
				&& (learnedRoute.iface == inIface);

		if (fromCurrentNextHop)
		{
			if (learnedMetric >= 16)
			{
				this.learnedRoutes.remove(routeKey);
				this.routeTable.remove(destAddr, subnetMask);
				return;
			}

			learnedRoute.metric = learnedMetric;
			learnedRoute.lastUpdate = now;
			learnedRoute.gatewayAddress = gatewayAddress;
			learnedRoute.iface = inIface;
			this.routeTable.update(destAddr, subnetMask, gatewayAddress, inIface);
			return;
		}

		if (learnedMetric < learnedRoute.metric)
		{
			learnedRoute.metric = learnedMetric;
			learnedRoute.lastUpdate = now;
			learnedRoute.gatewayAddress = gatewayAddress;
			learnedRoute.iface = inIface;
			this.routeTable.update(destAddr, subnetMask, gatewayAddress, inIface);
		}
	}
	/**
	 * Cancel RIP timers/tasks cleanly before calling super.destroy()
	 */
	@Override
	public void destroy() {
		if(this.ripEnabled) {
			this.ripResponseTimer.cancel();
		}
		super.destroy();
	}

}
