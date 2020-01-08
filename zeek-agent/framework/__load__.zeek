@load base/frameworks/cluster

@load ./configuration
@load ./framework_commons
@load ./hosts_send
@load ./zeek_agent_subscriptions

@if ( !Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER )
@load ./zeek_agent_hosts
@load ./bro_backend
@load ./zeek_agent_framework
@endif

@load ./zeek_logger
@load ./zeek_logger_log
