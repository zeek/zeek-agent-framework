
@load base/frameworks/broker
@load base/frameworks/logging

module zeek_agent;

export {
	## Subscribe to an event from clients. Whenever an zeek-agent connects to us, we'll subscribe to all matching
	## activity from it.
	##
	## The query is a mandatory parameter. It is send to a specific host and/or group (if specified). Otherwise (if
	## neither hosts nor group is given) the query is send to the broadcast group, such that all hosts will receive it.
	##
	## q: The query to subscribe to.
	## host: A specific host to address (optional).
	## group: A specific group to address (optional).
	global subscribe: function(q: Query, host: string &default="", group: string &default="");
	
	## Unsubscribe to an event from clients. This is sent to all clients that are currently connected and would match a
	## similar subscribe call.
	##
	## The query is a mandatory parameter. It is send to a specific host and/or group (if specified). Otherwise (if
	## neither hosts nor group is given) the query is send to the broadcast group, such that all hosts will receive it.
	##
	## q: The query to revoke.
	## host: A specific host to address (optional).
	## group: A specific group to address (optional).
	global unsubscribe: function(q: Query, host: string &default="", group: string &default="");
	
	## Subscribe to multiple events. Whenever an zeek-agent connects to us, we'll subscribe to all matching activity
	## from it.
	##
	## The queries is an mandatory parameter and contains 1 or more queries. Each of them is send to the specified hosts
	## and the specified groups. If neither is given, each query is broadcasted to all hosts.
	##
	## q: The query to subscribe to.
	## host_list: Specific hosts to address per query (optional).
	## group_list: Specific groups to address per query (optional).
	global subscribe_multiple: function(q: Query, host_list: vector of string &default=vector(""), group_list: vector of string &default=vector(""));
	
	## Unsubscribe from multiple events. This will get sent to all clients that are currently connected and would match
	## a similar subscribe call.
	##
	## The queries is an mandatory parameter and contains 1 or more queries. Each of them is send to the specified hosts
	## and the specified groups. If neither is given, each query is broadcasted to all hosts.
	##
	## q: The query to revoke.
	## host_list: Specific hosts to address per query (optional).
	## group_list: Specific groups to address per query (optional).
	global unsubscribe_multiple: function(q: Query, host_list: vector of string &default=vector(""), group_list: vector of string &default=vector(""));
	
	## Send a one-time query to all currently connected clients.
	##
	## The query is a mandatory parameter. It is send to a specific host and/or group (if specified). Otherwise (if
	## neither hosts nor group is given) the query is send to the broadcast group, such that all hosts will receive it.
	##
	## q: The query to execute.
	## host: A specific host to address (optional).
	## group: A specific group to address (optional).
	##
	## topic: The topic where the subscription is send to. All hosts in this group will
	## get the subscription.
	global execute: function(q: Query, host: string &default="", group: string &default="");
	
	## Send multiple one-time queries to all currently connected clients.
	##
	## The queries is an mandatory parameter and contains 1 or more queries. Each of them is send to the specified hosts
	## and the specified groups. If neither is given, each query is broadcasted to all hosts.
	##
	## q: The queriy to execute.
	## host_list: Specific hosts to address per query (optional).
	## group_list: Specific groups to address per query (optional).
	global execute_multiple: function(q: Query, host_list: vector of string &default=vector(""), group_list: vector of string &default=vector(""));
	
	## Make a subnet to be addressed by a group. Whenever an zeek-agent connects to us, we'll instruct it to join
	## the given group.
	##
	## range: the subnet that is addressed.
	## group: the group hosts should join.
	global join: function(range: subnet, group: string);
	
	## Revoke a grouping that a specific subnet should join a group.
	##
	## range: the subnet that is addressed.
	## group: the group hosts should leave.
	global leave: function(range: subnet, group: string);
	
	## Make a subnets to be addressed by a group. Whenever an zeek-agent connects to us, we'll instruct it to join
	## the given groups.
	##
	## range_list: the subnets that are addressed.
	## group: the group hosts should join.
	global join_multiple: function(range_list: vector of subnet, group: string);
	
	## Revoke a grouping that specific subnets should join a group.
	##
	## range_list: the subnet that is addressed.
	## group: the group hosts should leave.
	global leave_mutiple: function(range_list: vector of subnet, group: string);
}

function subscribe(q: Query, host: string, group: string)
	{
	local host_list = vector(host);
	local group_list = vector(group);
	subscribe_multiple(q, host_list, group_list);
	}

function subscribe_multiple(q: Query, host_list: vector of string, group_list: vector of string)
	{
	zeek_agent::share_subscription(q, host_list, group_list);
	zeek_agent::insert_subscription(q, host_list, group_list);
	}

function unsubscribe(q: Query, host: string, group: string)
	{
	local host_list = vector(host);
	local group_list = vector(group);
	unsubscribe_multiple(q, host_list, group_list);
	}

function unsubscribe_multiple(q: Query, host_list: vector of string, group_list: vector of string)
	{
	zeek_agent::unshare_subscription(q, host_list, group_list);
	zeek_agent::remove_subscription(q, host_list, group_list);
	}

function execute(q: Query, host: string, group: string)
	{
	local host_list = vector(host);
	local group_list = vector(group);
	execute_multiple(q, host_list, group_list);
	}

function execute_multiple(q: Query, host_list: vector of string, group_list: vector of string)
	{
	zeek_agent::share_execution(q, host_list, group_list);
	zeek_agent::insert_execution(q, host_list, group_list);
	}

function join(range: subnet, group: string)
	{
	local range_list = vector(range);
	join_multiple(range_list, group);
	}

function join_multiple(range_list: vector of subnet, group: string)
	{
	zeek_agent::share_grouping(range_list, group);
	zeek_agent::insert_grouping(range_list, group);
	}

function leave(range: subnet, group: string)
	{
	local range_list = vector(range);
	join_multiple(range_list, group);
	}

function leave_multiple(range_list: vector of subnet, group: string)
	{
	zeek_agent::unshare_grouping(range_list, group);
	zeek_agent::remove_grouping(range_list, group);
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	local peer_name = endpoint$id;

	if ( msg == "received handshake from remote core" )
		log_local("info", fmt("Outgoing connection established to %s", peer_name));
	else if ( msg == "handshake successful" )
		log_local("info", fmt("Incoming connection established from %s", peer_name));
	else
		log_local("info", fmt("Unkown connection established with %s", peer_name));
	}

event Broker::peer_removed(endpoint: Broker::EndpointInfo, msg: string)
	{
	local peer_name = endpoint$id;

	log_local("info", fmt("Removed connection with %s", peer_name));
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	local peer_name = endpoint$id;

	log_local("info", fmt("Lost connection with %s", peer_name));
	}

event Broker::status(endpoint: Broker::EndpointInfo, msg: string)
	{
	log_local("info", fmt("Status: %s", msg));
	}

event zeek_init() &priority=10
	{
	local topic = Zeek_ID_Topic;
	log_local("info", fmt("Subscribing to Broker topic %s", topic));
	Broker::subscribe(topic);

	log_local("info", fmt("Accepting incoming broker connections on IP %s and port %s", broker_ip, broker_port));
	Broker::listen(broker_ip, broker_port);
	}
