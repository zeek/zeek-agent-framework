##! Logs process events collected by Zeek Agent

@load zeek-agent

module Agent_ProcessEvents;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
            ts:         time   &log;
            host_ts:    time   &log;
            host:       string &log;
            hostname:   string &log;
            syscall:       string &log;
            uid:        int    &log;
            gid:        int    &log;
            ppid:     int    &log;
            pid:        int    &log;
            path:       string &log;
            exe:       string &log;
            cmdline:    string &log;
            cwd:        string &log;
    };
}

@if ( !Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER )
event Agent_ProcessEvents::process_event_logged(host_ts: time, host: string, hostname: string, syscall: string, pid: int, path: string, exe: string, cmdline: string, cwd: string,
        uid: int, gid: int, ppid: int)
    {
    local info = Info($ts = network_time(),
                    $host_ts = host_ts,
                    $host = host,
                    $hostname = hostname,
                    $syscall = syscall,
                    $uid = uid,
                    $gid = gid,
                    $ppid = ppid,
                    $pid = pid,
                    $path = path,
                    $exe = exe,
                    $cmdline = cmdline,
                    $cwd = cwd);

    Log::write(LOG, info);
    }

@endif

event zeek_init()
    {
    Log::create_stream(LOG, [$columns=Info, $path="agent_process_events"]);
    }
