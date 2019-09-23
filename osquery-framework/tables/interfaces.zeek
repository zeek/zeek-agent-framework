#! Query interfaces activity.

@load osquery-framework
@load ./configuration

module osquery;

export {
	## Event to indicate that a new interface was added on a host
	##
	## <params missing>
	global interface_added: event(t: time, host_id: string, interface: string, mac: string, ip: string, mask: string);
	
	## Event to indicate that a existing interface was removed on a host
	##
	## <params missing>
	global interface_removed: event(t: time, host_id: string, interface: string, mac: string, ip: string, mask: string);
}

event osquery::table_interfaces(resultInfo: osquery::ResultInfo,
	interface: string, mac: string, ip: string, mask: string) {
	# Remove interface name from IP
	if ("%" in ip) {
		# Find position of delimiter
		local i = 0;
		while (i < |ip|) {
			if (ip[i] == "%") break;
			i += 1;
		}
		ip = ip[:i];
	}

		if (resultInfo$utype == osquery::ADD) {
			event osquery::interface_added(network_time(), resultInfo$host, interface, mac, ip, mask);
	}
		if (resultInfo$utype == osquery::REMOVE) {
			event osquery::interface_removed(network_time(), resultInfo$host, interface, mac, ip , mask);
	}
}

event zeek_init() {
	local query = [$ev=osquery::table_interfaces,$query="SELECT d.interface, d.mac, a.address, a.mask FROM interface_addresses AS a INNER JOIN interface_details AS d ON a.interface=d.interface", $utype=osquery::BOTH, $inter=osquery::QUERY_INTERVAL];
	osquery::subscribe(query);
}
