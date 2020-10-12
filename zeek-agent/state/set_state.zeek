module ZeekAgent;

export {
	global socket_event_add: event(seuid: string, host_id: string, local_address: string, remote_address: string, local_port: int, remote_port: int);
}

event ZeekAgent::socket_event_add(seuid: string, host_id: string, local_address: string, remote_address: string, local_port: int, remote_port: int)
	{
	local connection_tuple = ZeekAgent::create_connection_tuple(local_address, remote_address, local_port, remote_port);

	local socket_info: ZeekAgent::SocketInfo = [$seuid=seuid, $connection=connection_tuple];

	event ZeekAgent::socket_event_add_worker(host_id, socket_info);

	Broker::publish(Cluster::worker_topic, Broker::make_event(ZeekAgent::socket_event_add_worker, host_id, socket_info));
	}
