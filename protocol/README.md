# Crux Protocol
The Crux Protocol is a trust-less information transfer (more specifically: websites) protocol. The protocol operates with similar concepts to that of onion routing. Crux Protocol ensures information that is relayed from the client to the webserver is completely oblivious to routing nodes in the connection "tunnel", this allows for enhanced privacy for the client. The Crux Protocol aims to be faster and more private than onion routing.

## Starting a connection
When a connection (to a webserver) is requested, the client picks a random known node to check if it has the IP address to the remote server, if it does not, this process will repeat until a node which knows an IP address matching the server's public key is found; this node is called the "final node".

At this point, the client will pick 6 random nodes and assign them a random order with the node which already knows the IP of the server being appended on the end. The client will sign the message, encrypt the message with the webserver's public key and then will use each of the tunnel node's public keys in the reverse order to "wrap" the message with layers of encryption (one for each node), similar to onion routing.

A HTTP request is sent to the tunnel, starting with the first node and ending with the final node. Each node will decrypt the request with their private key and forward to the next node in the tunnel.

Another way the Crux Protocol intends to be more secure than Tor is by randomly selecting a new tunnel on each request. This is possible by storing a public key for each node locally and having a system where nodes do not need to be told a request is coming. This allows the client to send a request to any node without agreeing on a new tunnel (tunnel is formed dynamically). The encrypted request will contain data in the decrypted element to instruct the node where to forward the request. This significantly reduces response times per request.
