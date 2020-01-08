#! Query processes activity.

@load osquery-framework
@load ./configuration

module osquery;

export {
	global process_open_sockets_added: event(t: time, host_id: string, pid: int, fd: int, family: int, protocol: int, local_address: string, remote_address: string, local_port: int, remote_port: int);
}

event osquery::table_process_open_sockets(resultInfo: osquery::ResultInfo, pid: int, fd: int, family: int, protocol: int, local_address: string, remote_address: string, local_port: int, remote_port: int)
	{
	if ( resultInfo$utype == osquery::ADD && pid != -1 )
		event osquery::process_open_sockets_added(network_time(), resultInfo$host, pid, fd, family, protocol, local_address, remote_address, local_port, remote_port);
	}

event zeek_init()
	{
	local query = [$ev=osquery::table_process_open_sockets, $query="SELECT pid, fd, family, protocol, local_address, remote_address, local_port, remote_port FROM process_open_sockets WHERE family=2", $utype=osquery::BOTH, $inter=osquery::QUERY_INTERVAL];
	osquery::subscribe(query);
	}
