##! Logs file events collected by Zeek Agent

@load zeek-agent

module Agent_FileEvents;

export {
    global file_event_logged: event(host_ts: time, host: string, hostname: string,syscall: string, pid: int, exe: string, path: string, inode: int);
}

event Agent_FileEvents::file_event_added(result: ZeekAgent::Result,
                                        syscall: string, pid: int, host_time: int, exe: string, path: string, inode: int)
    {
    if ( result$utype != ZeekAgent::ADD )
        return;
    local host_ts = double_to_time(host_time);
    event Agent_FileEvents::file_event_logged(host_ts, result$host, ZeekAgent::getHostInfo(result$host)$hostname, syscall, pid, exe, path, inode);
    }

event zeek_init()
    {
    local query = ZeekAgent::Query($ev=Agent_FileEvents::file_event_added,
                                    $query="SELECT syscall, pid, time, exe, path, inode FROM file_events",
                                    $utype=ZeekAgent::ADD);
    ZeekAgent::subscribe(query);
    }
