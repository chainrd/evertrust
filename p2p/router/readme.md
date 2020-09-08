P2P dynamic routing

P2P dynamic routing use the currnetly connected P2P network to construct a route table,
and use this table to forward msg to destination peer by peer.

There are three protocol messages to get P2P topology, TOPO_REQ(topology request), 
TOPO_RES(topology response), TOPO_INFO(topology inform), TOPO_REQ is used to get 
topology from neighbors and TOPO_RES is used to reply TOPO_REQ, and TOPO_INFO is 
used to inform updates to neighbors, who know the nodes in this updates, then Protocol 
routine will generate local route table 
