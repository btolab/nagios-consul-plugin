## What is this?

This is a consul check integration plugin for nagios that makes easy to add nagios commands that queries and aggregates specific checks or services by node from a consul agent.

Returns 2 if there are any critical checks, 1 if there are no criticals but warnings. Returns 3 when node not found or when there is no matches based on the given filters (CheckID, ServiceName). Returns 0 on passing checks.

## Example

Query the local consul agent for the serf health check of node named consul01 in datacenter dc01:
```
$ python check-consul-health.py node consul01 dc01 --CheckID=serfHealth
Passing: 1
> consul01::Serf Health Status:serfHealth:passing
```

Query for a specific service:
```
$ python check-consul-health.py node consul01 dc01 --ServiceName=raft
Passing: 2
> consul01:raft:Leader elected & operational:leader:passing
> consul01:raft:Peer list match:peers:passing
```

## Usage

```
$ python check-consul-health.py node -h
usage: check-consul-health.py node [-h] [--addr ADDR] [--verbose VERBOSE]
                                   [--CheckID CHECKID]
                                   [--ServiceName SERVICENAME]
                                   NODE DC

positional arguments:
  NODE                  the consul node_name
  DC                    the consul datacenter

optional arguments:
  -h, --help                show this help message and exit
  --addr ADDR               consul address [default: http://localhost:8500]
  --verbose VERBOSE         verbose output
  --CheckID CHECKID         CheckID matcher
  --ServiceName SERVICENAME ServiceName matcher
```

