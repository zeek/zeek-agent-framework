##! Logs socket events collected by Zeek Agent

@load zeek-agent
@load zeek-agent/state

module Agent_SocketEvents;

export {
        global socket_event_logged: event (host_ts: time, host: string, hostname: string, seuid: string, syscall: string, pid: int, fd: int, exe: string, local_address: string, remote_address: string, local_port: int, remote_port: int, success: int, uid: int);
}

event Agent_SocketEvents::socket_event_added(result: ZeekAgent::Result,
                                    syscall: string, pid: int, fd: int, exe: string, local_address: string, remote_address: string, local_port: int, remote_port: int, host_time: int, success: int, uid: int)
    {
    if ( result$utype != ZeekAgent::ADD )
        return;
    local host_ts = double_to_time(host_time);
    local seuid = unique_id("");
    event Agent_SocketEvents::socket_event_logged(host_ts, result$host, ZeekAgent::getHostInfo(result$host)$hostname, seuid, syscall, pid, fd, exe, local_address, remote_address, local_port, remote_port, success, uid);

    event ZeekAgent::socket_event_add(seuid, result$host, local_address, remote_address, local_port, remote_port);
    }

event zeek_init()
    {
    local query = ZeekAgent::Query($ev=Agent_SocketEvents::socket_event_added,
                                    $query="SELECT syscall, pid, fd, exe, local_address, remote_address, local_port, remote_port, time, success, uid FROM socket_events WHERE family=2",
                                    $utype=ZeekAgent::ADD);
    ZeekAgent::subscribe(query);
    }
