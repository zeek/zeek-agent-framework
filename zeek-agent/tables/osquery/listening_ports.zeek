#! Query listening ports activity

@load zeek-agent

module zeek_agent;

export {
	## Event to indicate that a new socket connection was created on a host
	##
	## <params missing>
	global listening_port_added: event(t: time, host_id: string, pid: int, fd: int, family: int, socket: int, protocol: int, local_address: string, local_port: int);
	
	## Event to indicate that an existing socket connection terminated on a host
	##
	## <params missing>
	global listening_port_removed: event(t: time, host_id: string, pid: int, fd: int, family: int, socket: int, protocol: int, local_address: string, local_port: int);
}

event zeek_agent::table_listening_ports(resultInfo: zeek_agent::ResultInfo,
pid: int, fd: int, family: int, socket: int, protocol: int, local_address: string, local_port: int) {
		if (resultInfo$utype == zeek_agent::ADD) {
			event zeek_agent::listening_port_added(network_time(), resultInfo$host, pid, fd, family, socket, protocol, local_address, local_port);
	}
		if (resultInfo$utype == zeek_agent::REMOVE) {
			event zeek_agent::listening_port_removed(network_time(), resultInfo$host, pid, fd, family, socket, protocol, local_address, local_port);
	}
}

event zeek_init() {
	local query = [$ev=zeek_agent::table_listening_ports,$query="SELECT pid, fd, family, socket, protocol, address, port FROM listening_ports WHERE family=2", $utype=zeek_agent::BOTH, $inter=zeek_agent::QUERY_INTERVAL];
	zeek_agent::subscribe(query);
}
