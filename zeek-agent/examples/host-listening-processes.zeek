@load zeek-agent

module HostListeningProcesses;

event HostListeningProcesses::found(result: zeek_agent::Result, process_name: string, cwd: string, protocol: int, local_addr: string, local_port: int)
	{
	print fmt("%s: %s process_name: %s  cwd: %s  protocol: %d  local_addr: %s   local_port: %d", result$host, result$utype, process_name, cwd, protocol, local_addr, local_port);
	}

event zeek_init()
	{
	local query = zeek_agent::Query($ev=HostListeningProcesses::found,
	                                $query="SELECT name, cwd, protocol, local_address, local_port FROM processes LEFT JOIN process_open_sockets WHERE processes.pid=process_open_sockets.pid AND process_open_sockets.state='LISTEN' AND local_address!='127.0.0.1' AND local_address!='::1'",
	                                $utype=zeek_agent::BOTH);
	zeek_agent::subscribe(query);
	}
