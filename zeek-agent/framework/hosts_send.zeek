@load base/frameworks/broker
@load base/frameworks/logging

module zeek_agent;

export
{
  ## The zeek-agent logging stream identifier.
  redef enum Log::ID += { LOG_SEND };

  ## Send a message to an zeek-agent or group of hosts to subscribe to a query
  ##
  ## topic: The topic of the host or group to address
  ## query: The query to subscribe to
  global send_subscribe: function(topic: string, query: zeek_agent::Query);

  ## Send a message to an zeek-agent or group of hosts to unsubscribe from a query
  ##
  ## topic: The topic of the host or group to address
  ## query: The query to unsubscribe from
  global send_unsubscribe: function(topic: string, query: zeek_agent::Query);

  ## Send a message to an zeek-agent or group of hosts to execute a query
  ##
  ## topic: The topic of the host or group to address
  ## query: The query to execute
  global send_execute: function(topic: string, q: zeek_agent::Query);

  ## Send a message to an zeek-agent or group of hosts to join a group
  ##
  ## host_topic: The topic of the host or group to address
  ## group: The group to join
  global send_join: function(host_topic: string, group: string);

  ## Send a message to an zeek-agent or group of hosts to leave a group
  ##
  ## host_topic: The topic of the host or group to address
  ## group: The group to leave
  global send_leave: function(host_topic: string, group: string);
}

# Sent by us to hosts for subscribing to an event.
global host_subscribe: event(ev: string, query: string, cookie: string, resT: string, utype: string, inter: count);

# Sent by us to hosts for unsubscribing from an event.
global host_unsubscribe: event(ev: string, query: string, cookie: string, resT: string, utype: string, inter: count);

# Sent by us to hosts for one-time query execution.
global host_execute: event(ev: string, query: string, cookie: string, resT: string, utype: string);

# Sent by us to hosts for join a group.
global host_join: event(group: string);

# Sent by us to hosts for leaving a group.
global host_leave: event(group: string);

function send_subscribe(topic: string, query: zeek_agent::Query)
{
    local ev_name = split_string(fmt("%s", query$ev), /\n/)[0];
    local host_topic = topic;

    zeek_agent::log("debug", topic, fmt("%s event %s() for query '%s'", "Subscribing to", ev_name, query$query), LOG_SEND);

    local update_type = "BOTH";
    if ( query$utype == zeek_agent::ADD )
        update_type = "ADDED";

    if ( query$utype == zeek_agent::REMOVE )
        update_type = "REMOVED";

    local cookie = query$cookie;

    local resT = topic;
    if ( query?$resT )
        resT = query$resT;
    Broker::subscribe(resT);

    local inter: count = 10;
    if ( query?$inter )
        inter = query$inter;

    local ev_args = Broker::make_event(host_subscribe, ev_name, query$query, cookie, resT, update_type, inter);
    Broker::publish(host_topic, ev_args);
}

function send_unsubscribe(topic: string, query: zeek_agent::Query)
{
    local ev_name = split_string(fmt("%s", query$ev), /\n/)[0];
    local host_topic = topic;

    zeek_agent::log("debug", topic, fmt("%s event %s() for query '%s'", "Unsubscribing from", ev_name, query$query), LOG_SEND);

    local update_type = "BOTH";
    if ( query$utype == zeek_agent::ADD )
        update_type = "ADDED";

    if ( query$utype == zeek_agent::REMOVE )
        update_type = "REMOVED";

    local cookie = query$cookie;

    local resT = topic;
    if ( query?$resT )
        resT = query$resT;

    local inter: count = 10;
    if ( query?$inter )
        inter = query$inter;

    local ev_args = Broker::make_event(host_unsubscribe, ev_name, query$query, cookie, resT, update_type, inter);
    Broker::publish(host_topic, ev_args);
}

function send_execute(topic: string, q: zeek_agent::Query)
{
    local ev_name = split_string(fmt("%s", q$ev), /\n/)[0];
    local host_topic = topic;

    zeek_agent::log("debug", topic, fmt("%s event %s() for query '%s'", "Executing", ev_name, q$query), LOG_SEND);

    local cookie = q$cookie;

    local resT = topic;
    if ( q?$resT )
        resT = q$resT;
    Broker::subscribe(resT);

    local ev_args = Broker::make_event(host_execute, ev_name, q$query, cookie, resT, "SNAPSHOT");
    Broker::publish(host_topic, ev_args);
}

function send_join(host_topic: string, group: string)
{
    zeek_agent::log("info", host_topic, fmt("%s group '%s'", "Joining", group), LOG_SEND);
    local ev_args = Broker::make_event(host_join, group);
    Broker::publish(host_topic, ev_args);
}

function send_leave(host_topic: string, group: string)
{
    zeek_agent::log("info", host_topic, fmt("%s group '%s'", "Leaving", group), LOG_SEND);
    local ev_args = Broker::make_event(host_leave, group);
    Broker::publish(host_topic, ev_args);
}

event zeek_init()
{
  Log::create_stream(LOG_SEND, [$columns=zeek_agent::Info, $path="zeek-agent-hosts"]);
}
