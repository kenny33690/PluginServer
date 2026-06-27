# Plugin Server
This project proposes a server for updating Unity plugins.
## Communication Protocal
- [ ] WS
We pass thorugh ws to comuunicate with server and client.  
We suggest both client and server should use a common CA cert. 
Beacause of MITM attack.

## Process
1. client sent a message: name,version,hash -> server 
