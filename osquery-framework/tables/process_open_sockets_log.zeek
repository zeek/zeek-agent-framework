#! Logs process open sockets activity

module osquery::logging::table_process_open_sockets;

export
{
	redef enum Log::ID += { LOG };

	type Info: record {
		t: time &log;
		host_id: string &log;
		pid: int &log;
		fd: int &log;
		family: int &log;
		protocol: int &log;
		local_address: string &log;
		remote_address: string &log;
		local_port: int &log;
		remote_port: int &log;
	};
}

@if (!Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER)
event osquery::process_open_sockets_added(t: time, host_id: string, pid: int, fd: int, family: int, protocol: int, local_address: string, remote_address: string, local_port: int, remote_port: int)
{
	local info: Info = [$t=t,
			    $host_id=host_id,
					$pid=pid,
					$fd=fd,
					$family=family,
					$protocol=protocol,
					$local_address=local_address,
					$remote_address=remote_address,
					$local_port=local_port,
					$remote_port=remote_port
			   ];

	Log::write(LOG, info);
}
@endif

event zeek_init()
{
	Log::create_stream(LOG, [$columns=Info, $path="osq-process_open_sockets"]);
}
