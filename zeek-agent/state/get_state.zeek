 module ZeekAgent;

export {
    global getSocketInfoByHostIDByConnection: function(host_id: string, input_connection: connection, src: bool &default=T): vector of SocketInfo;
    ## Get the Host Info of a host by its address
    global getHostIDsByAddress: function(a: addr): set[string];
}

function getSocketInfoByHostIDByConnection(host_id: string, input_connection: connection, src: bool): vector of SocketInfo
    {
    local input_connection_tuple = ZeekAgent::convert_conn_to_conntuple(input_connection, !src);
    local sockets_vec: vector of SocketInfo  = vector();
    local socket: ZeekAgent::SocketInfo;

    if ( host_id !in ZeekAgent::socket_events_state ) { return sockets_vec; }

    # Iterate over stored socket events to find input connection match
    for ( s_idx in ZeekAgent::socket_events_state[host_id] )
    {
        socket = ZeekAgent::socket_events_state[host_id][s_idx];
        if (matchConnectionTuple(input_connection_tuple, socket$connection))
        {
            sockets_vec += socket;
        }
    }

    return sockets_vec;
    }

function getHostIDsByAddress(a: addr): set[string]
    {
    local ip_addr = cat(a);
    if ( ip_addr in ipaddr_to_host ){
        return ipaddr_to_host[ip_addr];
    }else{
        return set();
    }
    }
