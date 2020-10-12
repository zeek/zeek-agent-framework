#! Query listening ports activity

@load zeek-agent

module AgentListeningPorts;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:           time &log;
		host:         string &log;
                hostname:     string &log;
		## Indicate if the port was "opened" or "closed".
		action:       string &log;
		address:      addr &log;
		listen_port:  int &log;
		protocol:     string &log;
		pid:          int &log;
		process_name: string &log;
	};

	const proto_lookup: table[int] of string = {
		[6] = "tcp",
		[17] = "udp",
		[132] = "sctp",
	} &redef &default=function(i: int): string { return fmt("unknown-%d", i); };
}

event AgentListeningPorts::listening_port(result: ZeekAgent::Result, pid: int, process_name: string, protocol: int, local_addr: string, local_port: int)
	{
	# Don't log existing open ports.  We only want the moment ports are opened or closed.
	if ( result$utype == ZeekAgent::INITIAL )
		return;

	# Remove interface name from IP and turn the string into an ip address
	local clean_addr = to_addr(split_string(local_addr, /\%/)[0]);

	local info = Info($ts = network_time(),
	                  $host = result$host,
			  $hostname = ZeekAgent::getHostInfo(result$host)$hostname,
	                  $action = result$utype == ZeekAgent::ADD ? "opened" : "closed",
	                  $pid = pid,
	                  $process_name = process_name,
	                  $protocol = proto_lookup[protocol],
	                  $address = clean_addr,
	                  $listen_port = local_port);

	Log::write(LOG, info);
	}

event zeek_init() &priority=10
	{
	Log::create_stream(LOG, [$columns=Info, $path="agent-listening-ports"]);

	# Family 2 is INET, so we're only watching for that.
	local query = ZeekAgent::Query($ev=AgentListeningPorts::listening_port,
	                                #$query="SELECT pid, protocol, address, port FROM listening_ports WHERE family=2",
	                                $query="SELECT listening_ports.pid, name, protocol, address, port FROM listening_ports LEFT JOIN processes WHERE processes.pid=listening_ports.pid AND family=2 AND address!='127.0.0.1' AND address!='::1';",
	                                $utype=ZeekAgent::BOTH);

	ZeekAgent::subscribe(query);
	}
