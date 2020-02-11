#! Logs socket events activity

@load zeek-agent

module Agent_SocketOpen;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:             time   &log;
		host_ts:        time   &log;
		host:           string &log;
		action:         string &log;
		pid:            int    &log;
		fd:             int    &log;
		path:           string &log;
		local_address:  addr   &log &default=0.0.0.0;
		remote_address: addr   &log &default=0.0.0.0;
		local_port:     int    &log;
		remote_port:    int    &log;
		success:        int    &log;
	};
}

event Agent_SocketOpen::socket_open(result: zeek_agent::ResultInfo, action: string, pid: int, fd: int, path: string, local_address: string, remote_address: string, local_port: int, remote_port: int, host_time: int, success: int)
	{
	if ( result$utype != zeek_agent::ADD )
		return;

	local host_ts = double_to_time(host_time);
	local info = Info($ts = network_time(),
	                  $host_ts = host_ts,
	                  $host = result$host,
	                  $pid = pid,
	                  $action = action,
	                  $fd = fd,
	                  $path = path,
	                  $local_port = local_port,
	                  $remote_port = remote_port,
	                  $success = success);

	if ( local_address != "" )
		info$local_address = to_addr(local_address);

	if ( remote_address != "" )
		info$remote_address = to_addr(remote_address);

	Log::write(LOG, info);
	}

event zeek_init() &priority=10
	{
	Log::create_stream(LOG, [$columns=Info, $path="agent-sockets_opening"]);

	local query = zeek_agent::Query($ev=Agent_SocketOpen::socket_open,
	                                $query="SELECT action, pid, fd, path, local_address, remote_address, local_port, remote_port, time, success FROM socket_events WHERE family=2",
	                                $utype=zeek_agent::ADD);
	zeek_agent::subscribe(query);
	}
