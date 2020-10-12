##! Logs process events collected by Zeek Agent

@load zeek-agent

module Agent_ProcessEvents;

export {
    global process_event_logged: event (host_ts: time, host: string, hostname: string, syscall: string, pid: int, path: string, exe: string, cmdline: string, cwd: string, uid: int, gid: int, ppid: int);
}

event Agent_ProcessEvents::process_event_added(result: ZeekAgent::Result,
                                            syscall: string, pid: int, path: string, exe: string, cmdline: string, cwd: string, uid: int, gid: int, host_time: int, ppid: int)
    {
    if ( result$utype != ZeekAgent::ADD )
        return;

    local host_ts = double_to_time(host_time);
    event Agent_ProcessEvents::process_event_logged(host_ts, result$host,
                ZeekAgent::getHostInfo(result$host)$hostname, syscall,
                pid, path, exe, cmdline, cwd, uid, gid, ppid);
    }

event zeek_init()
    {
    local query = ZeekAgent::Query($ev=Agent_ProcessEvents::process_event_added,
                                    $query="SELECT syscall, pid, path, exe, cmdline, cwd, uid, gid, time, ppid FROM process_events",
                                    $utype=ZeekAgent::ADD);
    ZeekAgent::subscribe(query);
    }
