##! Logs socket events collected by Zeek Agent

@load zeek-agent

module Agent_SocketEvents;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
            seuid:      string &log;
            ts:             time   &log;
            host_ts:        time   &log;
            host:           string &log;
            hostname:       string &log;
            syscall:         string &log;
            pid:            int    &log;
            fd:             int    &log;
            exe:           string &log;
            local_address:  addr   &log &default=0.0.0.0;
            remote_address: addr   &log &default=0.0.0.0;
            local_port:     int    &log;
            remote_port:    int    &log;
            success:        int    &log;
            uid:        int    &log;
    };
}

@if ( !Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER )
event Agent_SocketEvents::socket_event_logged(host_ts: time, host: string, hostname: string, seuid: string,
                        syscall: string, pid: int, fd: int, exe: string,
                                    local_address: string, remote_address: string,
                                    local_port: int, remote_port: int, success: int, uid: int)
    {
    local info = Info($seuid = seuid,
                    $ts = network_time(),
                    $host_ts = host_ts,
                    $host = host,
                    $hostname = hostname,
                    $syscall = syscall,
                    $pid = pid,
                    $fd = fd,
                    $exe = exe,
                    $local_port = local_port,
                    $remote_port = remote_port,
                    $success = success,
                    $uid = uid);

    if ( local_address != "" )
        info$local_address = to_addr(local_address);

    if ( remote_address != "" )
        info$remote_address = to_addr(remote_address);

    Log::write(LOG, info);
    }
@endif

event zeek_init()
    {
    Log::create_stream(LOG, [$columns=Info, $path="agent_socket_events"]);
    }
