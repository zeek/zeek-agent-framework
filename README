
# About

This Zeek script framework communicates with the [Zeek osquery
extension](https://github.com/zeek/osquery-extension) to perform live
queries against osquery tables and then incorporate the results back
into Zeek's processing & logging.

*Note*: This framework is still a work in progress and expected to
change further in terms of API, functionality, and implementation.
It's not also not been fully "Zeekified" yet.

# Prerequisites

The framework requires Zeek 3.0.0, which you can download and install
per the instructions on the [Zeek web site](https://zeek.org/download).

You will also need to install osquery and osquery Zeek extension
according to [these instructions](https://github.com/zeek/osquery-extension)).

# Installation

The easiest way to install this Zeek osquery framework, is through the
[Zeek package manager](https://docs.zeek.org/projects/package-manager/en/stable/index.html):

    # zkg install zeek/osquery-framework

Alternatively, you can clone the repository manually and copy it over
into Zeek's `site` folder:

    # git clone https://github.com/zeek/osquery-framework
    # cp -a osquery-framework/osquery-framework $(zeek-config --site_dir)

If you'd rather run it directly out of the local repository clone
(rather than `site`), set your `ZEEKPATH` accordingly:

    # export ZEEKPATH=<path/to/osquery-framework-repo>:$(zeek-config --zeekpath)

# Usage

Using any of the three installation methods above, you can now load
the framework when you start Zeek:

    # zeek osquery-framework

If you already have osqueryd running with the Zeek extension on an
endhost, you should now see a new Zeek log file `osquery.log` that
shows the host connecting to Zeek:

    # cat osquery.log
    #fields    ts        source   peer          level   message
    1569227664.061467    local    BroMaster     info    Subscribing to bro announce topic /bro/osquery/bro_announce
    1569227664.061467    local    BroMaster     info    Subscribing to bro individual topic /bro/osquery/bro/438471C1AD3BC467D02E991FBF767CABB5E36500#22035
    1569227690.750173    local    BroMaster     info    Incoming connection established from 438471C1AD3BC467D02E991FBF767CABB5E36500#22353
    1569227692.683012    host     example.org   info    Osquery host connected (438471C1AD3BC467D02E991FBF767CABB5E36500#22353 announced as: example.org)

You won't see much more at first as there's nothing sending queries to
the endhost yet. However, there's an additional set of scripts coming
with the framework that installs queries against selected tables and
turns the results into Zeek log files. You can enable these by loading
the `osquery-framework/tables` module:

    # zeek osquery-framework/tables

To enable these permanently, put `@load osquery-framework/tables` into
your `local.zeek` file.

Once enabled, you'll start seeing these additional Zeek log files:

- `osq-interface.log`: Records network interfaces added to a host.
- `osq-listening_ports.log`: Records network ports listening for incoming connections.
- `osq-mounts.log`: Records devices being mounted.
- `osq-prcocesses.log`: Records procsseses running on a host.
- `osq-process_events.log`: Likewise records processes, yet uses osquery's events-based table. That's more reliably, but requires osquery to be able to connect to Linux' audit system.
- `osq-process_open_sockets`: Records sockets being opened.
- `osq-socket_events`: Likewise records sockets being opened, using osquery's events-based table.
- `osq-users`: Records users being added to a host.

# Credits

This Zeek framework is based on an earlier implementation by [Steffan
Haas](https://github.com/iBigQ), with additonal work contributed by
[Corelight](https://www.corelight.com).
