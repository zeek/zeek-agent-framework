#! Logs listening ports activity

module zeek_agent::logging::table_listening_ports;

export {
        redef enum Log::ID += { LOG };

        type Info: record {
                t: time &log;
                host: string &log;
                pid: int &log;
                fd: int &log;
                family: int &log;
                socket: int &log;
                protocol: int &log;
                address: addr &log;
                listening_port: int &log;
        };
}

@if ( !Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER )
event zeek_agent::listening_port_added(t: time, host_id: string, pid: int, fd: int, family: int, socket: int, protocol: int, local_address: string, local_port: int) {
	local local_addr: addr;
	if (local_address != "") local_addr = to_addr(local_address);

        local info: Info = [
		$t=t,
		$host=host_id,
               	$pid = pid,
                $fd = fd,
                $socket = socket,
                $family = family,
                $protocol = protocol,
                $address = local_addr,
                $listening_port = local_port
        ];

        Log::write(LOG, info);
}
@endif

event zeek_init() {
        Log::create_stream(LOG, [$columns=Info, $path="agent-listening_ports"]);
}
