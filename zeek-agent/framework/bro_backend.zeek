@load base/frameworks/broker
@load base/frameworks/logging

@load ./framework_commons

module zeek_agent;

export {
	## Share subscription to an event with other zeek nodes.
	##
	## q: The query to subscribe to.
	## host_list: Specific hosts to address per query (optional).
	## group_list: Specific groups to address per query (optional).
	global share_subscription: function(q: zeek_agent::Query, host_list: vector of string &default=vector(""), group_list: vector of string &default=vector(""));
	
	## Revoke sharing of subscription to an events.
	##
	## q: The query to revoke.
	## host_list: Specific hosts to address per query (optional).
	## group_list: Specific groups to address per query (optional).
	global unshare_subscription: function(q: zeek_agent::Query, host_list: vector of string &default=vector(""), group_list: vector of string &default=vector(""));
	
	## Share a one-time query to all currently connected clients.
	##
	##
	## q: The query to execute.
	## host_list: Specific hosts to address per query (optional).
	## group_list: Specific groups to address per query (optional).
	global share_execution: function(q: zeek_agent::Query, host_list: vector of string &default=vector(""), group_list: vector of string &default=vector(""));
	
	## Share a grouping for organizing hosts in groups.
	##
	## range_list: the subnets that are addressed.
	## group: the group hosts should join.
	global share_grouping: function(range_list: vector of subnet, group: string);
	
	## Revoke sharing a grouping for organizing hosts in groups.
	##
	## range_list: the subnets that are addressed.
	## group: the group hosts should leave.
	global unshare_grouping: function(range_list: vector of subnet, group: string);
}

global zeek_new: event(peer_name: string, zeek_id: string, init: bool);

# Sent to share subscribing to an event.
global zeek_subscribe: event(group_flood: bool, via_peer_id: string, q: zeek_agent::Query, host_list: vector of string, group_list: vector of string);

# Sent to revoke subscribing to an event.
global zeek_unsubscribe: event(group_flood: bool, via_peer_id: string, q: zeek_agent::Query, host_list: vector of string, group_list: vector of string);

# Sent to share one-time query execution.
global zeek_execute: event(group_flood: bool, via_peer_id: string, q: zeek_agent::Query, host_list: vector of string, group_list: vector of string);

# Sent to share groupings hosts for join a group.
global zeek_join: event(group_flood: bool, via_peer_id: string, range_list: vector of subnet, group: string);

# Sent by us to hosts for leaving a group.
global zeek_leave: event(group_flood: bool, via_peer_id: string, range_list: vector of subnet, group: string);

# Internal table for tracking incoming subscriptions from remote
global zeek_subscriptions: table[string] of zeek_agent::Subscriptions;

# Internal table for tracking incoming assignments from remote
global zeek_groupings: table[string] of zeek_agent::Groupings;

# Internal mapping of broker id (peer_name) to zeek-agent (host_id)
global peer_to_zeek: table[string] of string;

function delete_zeek_subscription(query: zeek_agent::Query)
	{
	local peer_name = cat(Broker::node_id());
	local found = -1;
	
	# Find idx to delete
	for ( idx in zeek_subscriptions[peer_name] )
		{
		if ( zeek_agent::same_event(zeek_subscriptions[peer_name][idx]$query, query) )
			{
			found = idx;
			break;
			}
		}
	
	if ( idx == -1 )
		{
		# TODO Log
		return;
		}
	
	# New vector of new size
	local new_subscriptions: zeek_agent::Subscriptions;
	for ( idx in zeek_subscriptions[peer_name] )
		{
		if ( idx == found ) 
			next;
		
		new_subscriptions += zeek_subscriptions[peer_name][idx];
		}
	
	zeek_subscriptions[peer_name] = new_subscriptions;
	}

function delete_zeek_grouping(group: string)
	{
	local peer_name = cat(Broker::node_id());
	local found = -1;
	
	# Find idx to delete
	for ( idx in zeek_groupings[peer_name] )
		{
		if ( zeek_groupings[peer_name][idx]$group == group )
			{
			found = idx;
			break;
			}
		}
	
	if ( idx == -1 )
		{
		# TODO Log
		return;
		}
	
	# New vector of new size
	local new_groupings: zeek_agent::Groupings;
	for ( idx in zeek_groupings[peer_name] )
		{
		if ( idx == found )
			next;
		
		new_groupings += zeek_groupings[peer_name][idx];
		}
	
	zeek_groupings[peer_name] = new_groupings;
	}

function send_subscription(topic: string, ev: any, group_flood: bool, q: zeek_agent::Query, host_list: vector of string &default=vector(""), group_list: vector of string &default=vector(""))
	{
	local ev_name = split_string(fmt("%s", ev), /\n/)[0];
	zeek_agent::log_zeek("debug", topic, fmt("%s event %s() for query '%s'", "Forwarding", ev_name, q$query));
	
	local ev_args = Broker::make_event(ev, group_flood, fmt("%s",Broker::node_id()), q, host_list, group_list);
	Broker::publish(topic, ev_args);
	}

function send_grouping(topic: string, ev: any, group_flood: bool, range_list: vector of subnet, group: string)
	{
	local ev_name = split_string(fmt("%s", ev), /\n/)[0];
	zeek_agent::log_zeek("debug", topic, fmt("%s event %s() for group '%s'", "Forwarding", ev_name, group));
	
	local ev_args = Broker::make_event(ev, group_flood, cat(Broker::node_id()), range_list, group);
	Broker::publish(topic, ev_args);
	}

function share_subscription(q: zeek_agent::Query, host_list: vector of string &default=vector(""), group_list: vector of string &default=vector(""))
	{
	local peer_name = cat(Broker::node_id());
	if ( peer_name !in zeek_subscriptions )
		zeek_subscriptions[peer_name] = vector();
	
	zeek_subscriptions[peer_name] += Subscription($query=q, $hosts=host_list, $groups=group_list);
	send_subscription(zeek_agent::ZeekBroadcastTopic, zeek_subscribe, T, q, host_list, group_list);
	}

function unshare_subscription(q: zeek_agent::Query, host_list: vector of string &default=vector(""), group_list: vector of string &default=vector(""))
	{
	delete_zeek_subscription(q);
	send_subscription(zeek_agent::ZeekBroadcastTopic, zeek_unsubscribe, T, q, host_list, group_list);
	}

function share_execution(q: zeek_agent::Query, host_list: vector of string &default=vector(""), group_list: vector of string &default=vector(""))
	{
	send_subscription(zeek_agent::ZeekBroadcastTopic, zeek_execute, T, q, host_list, group_list);
	}

function share_grouping(range_list: vector of subnet, group: string)
	{
	local peer_name = cat(Broker::node_id());
	if ( peer_name !in zeek_groupings )
		zeek_groupings[peer_name] = vector();
	
	zeek_groupings[peer_name] += Grouping($group=group, $ranges=range_list);
	send_grouping(zeek_agent::ZeekBroadcastTopic, zeek_join, T, range_list, group);
	}

function unshare_grouping(range_list: vector of subnet, group: string)
	{
	delete_zeek_grouping(group);
	send_grouping(zeek_agent::ZeekBroadcastTopic, zeek_leave, T, range_list, group);
	}

event zeek_agent::zeek_subscribe(group_flood: bool, via_peer_id: string, q: zeek_agent::Query, host_list: vector of string, group_list: vector of string)
	{
	# Keep state about the direction the subscription came from
	local topic: string;
	if ( via_peer_id !in zeek_subscriptions )
		{
		topic = fmt("%s/%s", zeek_agent::ZeekIndividualTopic, via_peer_id);
		zeek_agent::log_zeek("warning", topic, fmt("Unexpected event %s from unknown Zeek for query %s", "zeek_subscribe", q$query));
		return;
		}
	
	zeek_agent::insert_subscription(q, host_list, group_list);
	zeek_subscriptions[via_peer_id] += Subscription($query=q, $hosts=host_list, $groups=group_list);

	# Group Flooding will be done automatically in Broker
	if ( group_flood )
		return;

	# Forward subscription manually to all other neighbors
	local peer_name: string;
	for ( peer_name in peer_to_zeek )
		{
		if (peer_name == via_peer_id)
			next;

		topic = fmt("%s/%s", zeek_agent::ZeekIndividualTopic, peer_name);
		send_subscription(topic, zeek_subscribe, F, q, host_list, group_list);
		}
	}

event zeek_agent::zeek_unsubscribe(group_flood: bool, via_peer_id: string, q: zeek_agent::Query, host_list: vector of string, group_list: vector of string)
	{
	# Remove state about the direction the subscription came from
	local topic: string;
	if ( via_peer_id !in zeek_subscriptions )
		{
		topic = fmt("%s/%s", zeek_agent::ZeekIndividualTopic, via_peer_id);
		zeek_agent::log_zeek("warning", topic, fmt("Unexpected event %s from unkown Zeek for query %s", "zeek_unsubscribe", q$query));
		return;
		}
	
	zeek_agent::remove_subscription(q, host_list, group_list);
	delete_zeek_subscription(q);
		
	# Group Flooding will be done automatically in Broker
	if ( group_flood )
		return;
		
	# Forward unsubscription manually to all other neighbors
	local peer_name: string;
	for ( peer_name in peer_to_zeek )
		{
		if ( peer_name == via_peer_id )
			next;
		
		topic = fmt("%s/%s", zeek_agent::ZeekIndividualTopic, peer_name);
		send_subscription(topic, zeek_unsubscribe, F, q, host_list, group_list);
		}
	}

event zeek_agent::zeek_execute(group_flood: bool, via_peer_id: string, q: zeek_agent::Query, host_list: vector of string, group_list: vector of string)
	{
	# Apply execution locallzeek_agentsert_execution(q, host_list, group_list);
	
	# Group Flooding will be done automatically in Broker
	if ( group_flood )
		return;
	
	# Forward subscription manually to all other neighbors
	for ( peer_name in peer_to_zeek )
		{
		if ( peer_name == via_peer_id )
			next;
		
		local topic = fmt("%s/%s", zeek_agent::ZeekIndividualTopic, peer_name);
		send_subscription(topic, zeek_subscribe, F, q, host_list, group_list);
		}
	}

event zeek_agent::zeek_join(group_flood: bool, via_peer_id: string, range_list: vector of subnet, group: string)
	{
	# Keep state about the direction the subscription came from
	local topic: string;
	if ( via_peer_id !in zeek_groupings )
		{
		topic = fmt("%s/%s", zeek_agent::ZeekIndividualTopic, via_peer_id);
		zeek_agent::log_zeek("warning", topic, fmt("Unexpected event %s from unkown Zeek for group %s", "zeek_join", group));
		return;
		}
	
	zeek_agent::insert_grouping(range_list, group);
	zeek_groupings[via_peer_id] += Grouping($group=group, $ranges=range_list);
	
	# Group Flooding will be done automatically in Broker
	if ( group_flood )
		return;
	
	# Forward grouping manually to all other neighbors
	for ( peer_name in peer_to_zeek )
		{
		if ( peer_name == via_peer_id )
			next;
		
		topic = fmt("%s/%s", zeek_agent::ZeekIndividualTopic, peer_name);
		send_grouping(topic, zeek_join, F, range_list, group);
		}
	}

event zeek_agent::zeek_leave(group_flood: bool, via_peer_id: string, range_list: vector of subnet, group: string)
	{
	# Remove state about the direction the subscription came from
	local topic: string;
	if ( via_peer_id !in zeek_groupings )
		{
		topic = fmt("%s/%s", zeek_agent::ZeekIndividualTopic, via_peer_id);
		zeek_agent::log_zeek("warning", topic, fmt("Unexpected event %s from unknown Zeek for group %s", "zeek_leave", group));
		return;
		}
	
	zeek_agent::remove_grouping(range_list, group);
	delete_zeek_grouping(group);
	
	# Group Flooding will be done automatically in Broker
	if ( group_flood )
		return;
	
	# Forward grouping manually to all other neighbors
	local peer_name: string;
	for ( peer_name in peer_to_zeek )
		{
		if ( peer_name == via_peer_id )
			next;
		
		topic = fmt("%s/%s", zeek_agent::ZeekIndividualTopic, peer_name);
		send_grouping(topic, zeek_leave, F, range_list, group);
		}
	}

event zeek_agent::zeek_new(peer_name: string, zeek_id: string, init: bool)
	{
	zeek_agent::log_zeek("info", zeek_id, fmt("Zeek Backend connected (%s announced as %s)", peer_name, zeek_id));
	local topic = fmt("%s/%s", zeek_agent::ZeekIndividualTopic, peer_name);
	
	# Zeek already known?
	if ( peer_name in peer_to_zeek )
		{
		local topic_from = fmt("%s/%s", zeek_agent::ZeekIndividualTopic, peer_name);
		zeek_agent::log_zeek("warning", topic_from, fmt("Peer %s with ID %s already known as Zeek", peer_name, zeek_id));
		}
	
	# Internal client tracking
	peer_to_zeek[peer_name] = zeek_id;
	zeek_subscriptions[peer_name] = vector();
	zeek_groupings[peer_name] = vector();
	
	# Also announce back to retrieve their state
	if ( init )
		{
		local ev_args = Broker::make_event(zeek_new, fmt("%s",Broker::node_id()), zeek_agent::Zeek_ID_Topic, F);
		Broker::publish(topic, ev_args);
		}
	
	# Send own subscriptions
	local s: zeek_agent::Subscription;
	for ( p_name in zeek_subscriptions )
		{
		if ( p_name == peer_name )
			next;
		
		for ( i in zeek_subscriptions[p_name] )
			{
			s = zeek_subscriptions[p_name][i];
			send_subscription(topic, zeek_subscribe, F, s$query, s$hosts, s$groups);
			}
		}
	
	# Send own groupings
	local g: zeek_agent::Grouping;
	for ( p_name in zeek_groupings )
		{
		if ( p_name == peer_name )
			next;
		
		for ( i in zeek_groupings[p_name] )
			{
			g = zeek_groupings[p_name][i];
			send_grouping(topic, zeek_join, F, g$ranges, g$group);
			}
		}
	
	# raise event for new zeek
	event zeek_agent::bro_connected(zeek_id);
	}

function revoke_subscriptions(peer_name: string, disconnected: bool &default=T)
	{
	for ( i in zeek_subscriptions[peer_name] )
		{
		local s = zeek_subscriptions[peer_name][i];
	
		# Remove locally
		zeek_agent::remove_subscription(s$query, s$hosts, s$groups);
		
		# Generate unsubscribe caused by disconnect
		if ( disconnected )
			{
			# Safe to flood the unsubscribe
			local topic = zeek_agent::ZeekBroadcastTopic;
			send_subscription(topic, zeek_unsubscribe, T, s$query, s$hosts, s$groups);
			} 
		else
			{
			# TODO: Remove manually by individual messages to other neighbors
			}
		}
	
	# Remove State
	delete zeek_subscriptions[peer_name];
	}

function revoke_groupings(peer_name: string, disconnected: bool &default=T)
	{
	local g: zeek_agent::Grouping;
	for ( i in zeek_groupings[peer_name] )
		{
		g = zeek_groupings[peer_name][i];
	
		# Remove locally
		zeek_agent::remove_grouping(g$ranges, g$group);
		
		# Generate unsubscribe caused by disconnect
		if ( disconnected )
			{
			# Safe to flood the unsubscribe
			local topic: string = zeek_agent::ZeekBroadcastTopic;
			send_grouping(topic, zeek_leave, T, g$ranges, g$group);
			}
		else
			{
			# TODO: Remove manually by individual messages to other neighbors
			}
		}
	
	# Remove State
	local g_list: vector of zeek_agent::Grouping;
	zeek_groupings[peer_name] = g_list;
	}

event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string)
	{
	# Only for outgoing connections
	if ( msg != "received handshake from remote core" )
		return;
	
	local peer_name: string = {endpoint$id};
	local topic: string = fmt("%s/%s", zeek_agent::ZeekIndividualTopic, peer_name);
	
	# Send announce message to the remote peer
	local ev_args = Broker::make_event(zeek_new, fmt("%s",Broker::node_id()), zeek_agent::Zeek_ID_Topic, T);
	Broker::publish(topic, ev_args);
	}

event Broker::peer_removed(endpoint: Broker::EndpointInfo, msg: string)
	{
	local peer_name: string = {endpoint$id};
	if ( peer_name !in zeek_subscriptions )
		return;
	
	local zeek_id: string = peer_to_zeek[peer_name];
	zeek_agent::log_zeek("info", zeek_id, "Zeek disconnected");
	
	# Revoke all subscriptions that came in via this peer
	revoke_subscriptions(peer_name);
	revoke_groupings(peer_name);
	delete zeek_subscriptions[peer_name];
	delete zeek_groupings[peer_name];
	delete peer_to_zeek[peer_name];
	
	# raise event for disconnected bro
	event zeek_agent::bro_disconnected(zeek_id);
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	local peer_name: string = {endpoint$id};
	if ( peer_name !in zeek_subscriptions )
		return;
	
	local zeek_id: string = peer_to_zeek[peer_name];
	zeek_agent::log_zeek("info", zeek_id, "Zeek disconnected");
	
	# Revoke all subscriptions that came in via this peer
	revoke_subscriptions(peer_name);
	revoke_groupings(peer_name);
	delete zeek_subscriptions[peer_name];
	delete zeek_groupings[peer_name];
	delete peer_to_zeek[peer_name];
	
	# raise event for disconnected zeek
	event zeek_agent::bro_disconnected(zeek_id);
	}

event zeek_init()
	{
	# Listen on Zeek announce topic
	local topic: string = zeek_agent::ZeekAnnounceTopic;
	zeek_agent::log_local("info", fmt("Subscribing to Zeek announce topic %s", topic));
	Broker::subscribe(topic);
	
	# Listen on Zeek individual topic
	topic = fmt("%s/%s", zeek_agent::ZeekIndividualTopic, Broker::node_id());
	zeek_agent::log_local("info", fmt("Subscribing to Zeek individual topic %s", topic));
	Broker::subscribe(topic);
	
	# Connect to remote Zeek
	if ( |zeek_agent::backend_ip| != 0 && 
	     zeek_agent::backend_ip != "0.0.0.0" )
		{
		Broker::peer(zeek_agent::backend_ip, zeek_agent::backend_port, 10sec);
		}
	}
