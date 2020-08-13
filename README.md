# Ryu Network Awareness

Forked from https://github.com/muzixing/ryu/tree/master/ryu/app/network_awareness

## Installation

Some code in Ryu library needs to be changed. See https://github.com/muzixing/ryu/tree/master/ryu/app/network_awareness for more information.

## Run

```
$ ryu run ryu.app.network_awareness.shortest_forwarding ryu.app.network_awareness.statistics_server ryu.app.ofctl_rest --observe-links --k-paths=5 --weight=all
```

## Contributors

* Li Cheng (original author of the network_awareness app)
* Peter Zhang
* Marco Perez Hernandez
