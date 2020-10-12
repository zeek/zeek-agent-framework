##! Logs socket events collected by Zeek Agent

@load zeek-agent

module Agent_FileEvents;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
            ts:             time   &log;
            host_ts:        time   &log;
            host:           string &log;
            hostname:       string &log;
            syscall:         string &log;
            pid:            int    &log;
            exe:        string    &log;
            path:        string    &log;
            inode:        int    &log;
    };
}

@if ( !Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER )
event Agent_FileEvents::file_event_logged(host_ts: time, host: string, hostname: string,syscall: string, pid: int,
                    exe: string, path: string, inode: int)
    {
    local info = Info($ts = network_time(),
                    $host_ts = host_ts,
                    $host = host,
                    $hostname = hostname,
                    $syscall = syscall,
                    $pid = pid,
                    $exe = exe,
                    $path = path,
                    $inode = inode);

    Log::write(LOG, info);
    }

@endif

event zeek_init()
    {
    Log::create_stream(LOG, [$columns=Info, $path="agent_file_events"]);
    }
