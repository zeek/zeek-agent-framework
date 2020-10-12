#! Provide socket state utils

module ZeekAgent;

export {
    global matchConnectionTuple: function(conn: ConnectionTuple, conn_pattern: ConnectionTuple): bool;
    global convert_conn_to_conntuple: function(c: connection, reverse: bool): ConnectionTuple;
    global equalSocketInfos: function(sock1: SocketInfo, sock2: SocketInfo): bool;
    global create_connection_tuple: function(local_address: string, remote_address: string, local_port: int, remote_port: int): ConnectionTuple;
}

function convert_conn_to_conntuple(c: connection, reverse: bool): ConnectionTuple
    {
    local local_port: int = port_to_count(c$id$orig_p) + 0;
    local remote_port: int = port_to_count(c$id$resp_p) + 0;

    if ( reverse ) {
        return [$local_address=c$id$resp_h, $remote_address=c$id$orig_h, $local_port=remote_port, $remote_port=local_port];
    }

    return [$local_address=c$id$orig_h, $remote_address=c$id$resp_h, $local_port=local_port, $remote_port=remote_port];
    }

function equalConnectionTuples(conn1: ConnectionTuple, conn2: ConnectionTuple): bool
    {
    if (conn1?$local_address != conn2?$local_address) {
        return F;
    }
    if (conn1?$local_address && conn1$local_address != conn2$local_address) {
        return F;
    }
    if (conn1?$remote_address != conn2?$remote_address) {
        return F;
    }
    if (conn1?$remote_address && conn1$remote_address != conn2$remote_address) {
        return F;
    }
    if (conn1?$local_port != conn2?$local_port) {
        return F;
    }
    if (conn1?$local_port && conn1$local_port != conn2$local_port) {
        return F;
    }
    if (conn1?$remote_port != conn2?$remote_port) {
        return F;
    }
    if (conn1?$remote_port && conn1$remote_port != conn2$remote_port) {
        return F;
    }
    return T;
    }

function equalSocketInfos(sock1: SocketInfo, sock2: SocketInfo): bool
    {
    if (!equalConnectionTuples(sock1$connection, sock2$connection)) {
        return F;
    }

    return T;
    }

function create_connection_tuple(local_address: string, remote_address: string, local_port: int, remote_port: int): ConnectionTuple
    {
    local connection_tuple: ConnectionTuple = [];
    if ( local_address != "" ) { connection_tuple$local_address = to_addr(local_address); }
    if ( remote_address != "" ) { connection_tuple$remote_address = to_addr(remote_address); }
    if ( local_port != 0 ) { connection_tuple$local_port = local_port; }
    if ( remote_port != 0 ) { connection_tuple$remote_port = remote_port; }

    return connection_tuple;
    }

function matchConnectionTuple(conn: ConnectionTuple, conn_pattern: ConnectionTuple): bool
    {
    if (conn_pattern?$local_address && conn_pattern$local_address != 0.0.0.0 && (!conn?$local_address || conn$local_address != conn_pattern$local_address)) {
        return F;
    }

    if (conn_pattern?$local_port && conn_pattern$local_port != 0 && (!conn?$local_port || conn$local_port != conn_pattern$local_port)) {
        return F;
    }

    if (conn_pattern?$remote_address && conn_pattern$remote_address != 0.0.0.0 && (!conn?$remote_address || conn$remote_address != conn_pattern$remote_address)) {
        return F;
    }

    if (conn_pattern?$remote_port && conn_pattern$remote_port != 0 && (!conn?$remote_port || conn$remote_port != conn_pattern$remote_port)) {
        return F;
    }

    return T;
    }

