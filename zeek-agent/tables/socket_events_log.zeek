#! Logs socket events activity

module zeek_agent::logging::table_socket_events;

export {
        redef enum Log::ID += { LOG };

        type Info: record {
                t: time &log;
                host: string &log;
                action: string &log;
                pid: int &log;
                fd: int &log;
                path: string &log;
                family: int &log;
                local_address: addr &log;
                remote_address: addr &log;
                local_port: int &log;
                remote_port: int &log;
		start_time: int &log;
		success: int &log;
        };
}

@if ( !Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER )
event zeek_agent::socket_event_added(t: time, host_id: string, action: string, pid: int, fd: int, path: string, family: int, local_address: string, remote_address: string, local_port: int, remote_port: int, start_time: int, success: int) {
        if (action == "connect" || local_address == "") {
          local_address = "0.0.0.0";
        }
        if (action == "bind" || remote_address == "") {
          remote_address = "0.0.0.0";
        }

        local info: Info = [
		$t=t,
		$host=host_id,
                $action = action,
               	$pid = pid,
               	$fd = fd,
                $path = path,
                $family = family,
                $local_address = to_addr(local_address),
                $remote_address = to_addr(remote_address),
                $local_port = local_port,
                $remote_port = remote_port,
                $start_time = start_time,
                $success = success
        ];

        Log::write(LOG, info);
}
@endif

event zeek_init() {
        Log::create_stream(LOG, [$columns=Info, $path="agent-socket_events"]);
}
