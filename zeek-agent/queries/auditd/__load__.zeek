# Load process, file, and socket events tables that are built into zeek-agent

@if ( !Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER )
@load ./process-events
@load ./socket-events
@load ./file-events
@endif

@load ./process-events-log
@load ./socket-events-log
@load ./file-events-log
