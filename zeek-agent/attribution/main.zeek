#! Attribution of Zeek network connections to socket_events enteries from hosts
module ZeekAgent;

export {
    global connection_attributing: hook(c: connection, src_attributions: vector of SocketInfo, dst_attributions: vector of SocketInfo);
}

function attribute_connection(c: connection)
    {
    # - Get list of hosts with this source IP
    local src_host_ids = ZeekAgent::getHostIDsByAddress(c$id$orig_h);
    # - Get list of hosts with this target IP
    local dst_host_ids = ZeekAgent::getHostIDsByAddress(c$id$resp_h);

    if (|src_host_ids| + |dst_host_ids| == 0)
    {
        return;
    }

    local src_attributions: vector of SocketInfo;
    local dst_attributions: vector of SocketInfo;

    for ( host_id in src_host_ids )
    {
        src_attributions = ZeekAgent::getSocketInfoByHostIDByConnection(host_id, c);
    }

    for ( host_id in dst_host_ids )
    {
        dst_attributions = ZeekAgent::getSocketInfoByHostIDByConnection(host_id, c, F);
    }

    hook ZeekAgent::connection_attributing(c, src_attributions, dst_attributions);
    }

event connection_state_remove(c: connection)
    {
    attribute_connection(c);
    }
