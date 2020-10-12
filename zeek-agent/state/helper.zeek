module ZeekAgent;

event ZeekAgent::socket_event_add_worker(host_id: string, socket_info: ZeekAgent::SocketInfo)
	{
	if ( host_id in ZeekAgent::socket_events_state ){
		ZeekAgent::socket_events_state[host_id] += socket_info;
	}
	else{
		ZeekAgent::socket_events_state[host_id] = vector(socket_info);
	}
	}

event ZeekAgent::host_ipaddr_add_worker(host_id: string, ip_addr: string) {
	if (ip_addr in ipaddr_to_host){
		add ipaddr_to_host[ip_addr][host_id];
	}else{
		ipaddr_to_host[ip_addr] = set(host_id);
	}
}

