package edu.wisc.cs.sdn.vnet.sw;

import net.floodlightcontroller.packet.Ethernet;
import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;
import net.floodlightcontroller.packet.MACAddress;
import java.util.Map;
import java.util.HashMap;
import java.time.Instant;
/**
 * @author Aaron Gember-Jacobson
 */
public class Switch extends Device
{	
	/**
	 * private class meant for storing MacEntry information
	 * 
	 */
	private static class MacEntry{
		Iface iface;
		long insertTime;
		/**
		 * Creates MacEntry object for an entry into the macTable
		 * @param iface interface mapped to mac address
		 * @param insertTime time entry was created in seconds
		 */
		MacEntry(Iface iface, long insertTime){
			this.iface = iface;
			this.insertTime = insertTime;

		}
	}

	private Map<MACAddress, MacEntry> macTable = new HashMap<>();
	private final long MAC_ENTRY_TTL = 15L; 
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Switch(String host, DumpFile logfile)
	{
		super(host,logfile);
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * 
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface     the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface) {

		// use getSourceMAC to get the source MAC address of the packet
		MACAddress sourceMAC = etherPacket.getSourceMAC();

		// use getDestinationMAC to get the destination MAC address of the packet
		MACAddress destinationMAC = etherPacket.getDestinationMAC();

		// regardless for every situation insert, revalidate, insert due to last entry
		// expering
		// we need to update the value in our map and put either adds or overides old
		// value
		// Instant.now().getEpochSecond because granularity of 1 second is ok
		long now = Instant.now().getEpochSecond();
		// also fine to make new MacEntry object every time, it doesn't have much
		// overhead
		macTable.put(sourceMAC, new MacEntry(inIface, now));

		boolean successfullySent = false;

		MacEntry entry = macTable.get(destinationMAC);
		// if we have seen the destination mac before
		if (entry != null) {
			// if the entry is still valid, send the packet
			if (now - entry.insertTime <= MAC_ENTRY_TTL) {
				Iface outgoingIface = entry.iface;
				// drop frames learned on the same incoming interface
				if (outgoingIface.getName().equals(inIface.getName())) {
					successfullySent = true;
				} else {
					// try to send packet
					successfullySent = super.sendPacket(etherPacket, outgoingIface);
					// if we couldn't send, remove entry from map to be sure its no longer used
					if (!successfullySent) {
						macTable.remove(destinationMAC);
					}
				}
			}
			// entry is expired, remove from mactable
			else {
				macTable.remove(destinationMAC);
			}
		}
		// if the mac address wasn't present/valid or our send was unsuccessful,
		// broadcast
		if (!successfullySent) {
			// refresh now for broadcast
			now = Instant.now().getEpochSecond();
			Map<String, Iface> allIfaces = super.getInterfaces();

			for (Iface curIface : allIfaces.values()) {
				// if interface we are checking isnt same as incoming
				if (!curIface.getName().equals(inIface.getName())) {
					// broadcast to every interface on our switch, true is returned if packet was
					// sent successfully, but that
					// doesn't matter as it can be successfully sent to all interfaces, not just the
					// one we want
					super.sendPacket(etherPacket, curIface);
				}

			}
		}
	}
}
