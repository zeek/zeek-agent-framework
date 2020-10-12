#! Log attribution with agent_socket_events by extending conn.log

module ZeekAgent;

# Add attribution fields to the conn.log record.
redef record Conn::Info += {
    # agent_socket_events.log seuid on the originating system
    orig_seuids: set[string] &optional &log;

    # agent_socket_events.log seuid on the responding system
    resp_seuids: set[string] &optional &log;
};

hook ZeekAgent::connection_attributing(c: connection, src_attributions: vector of ZeekAgent::SocketInfo, dst_attributions: vector of ZeekAgent::SocketInfo)
    {

    local socket: ZeekAgent::SocketInfo;

    for ( idx in src_attributions ) {
        socket = src_attributions[idx];
        if (!c$conn?$orig_seuids) {c$conn$orig_seuids = set(socket$seuid);}
        else {add c$conn$orig_seuids[socket$seuid];}
    }

    for ( idx in dst_attributions ) {
        socket = dst_attributions[idx];
        if (!c$conn?$resp_seuids) {c$conn$resp_seuids = set(socket$seuid);}
        else {add c$conn$resp_seuids[socket$seuid];}
    }
    }
