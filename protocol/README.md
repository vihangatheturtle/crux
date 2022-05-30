# Crux Protocol
The Crux Protocol is a trust-less information transfer (more specifically: websites) protocol. The protocol operates with similar concepts to that of onion routing. Crux Protocol ensures information that is relayed from the client to the webserver is completely oblivious to routing nodes in the connection "tunnel", this allows for enhanced privacy for the client. The Crux Protocol aims to be faster and more private than onion routing.

**Contents**
 - [Starting a connection](#start-a-connection)

## Starting a connection {#start-a-connection}
When a connection (to a webserver) is requested, the client picks a random known node to check if it has the IP address to the remote server, if it does not, this process will repeat until a node which knows an IP address matching the server's public key is found; this node is called the "final node".

At this point, the client will pick 6 random nodes and assign them a random order with the node which already knows the IP of the server being appended on the end. 

A HTTP request is sent to the tunnel, starting with the first node and ending with the final node. Each node will encrypt the request with the webserver's public key and then sign the payload with their private key. The node's public key is also added to the request's metadata. This allows the receiving server to verify each node has not tampered with the message by reversing the encryption process and confirming that each signature is valid. The first request sent through the tunnel is an insecure request to fetch the webserver's public key (this is only ever done if the client does not already know it).

Forwarded requests never contain information that links back to the previous node/client. The node stores information about the previous client in the request's object. This ensures that requests cannot be easily traced back to the client if a node has been compromised.

When a node receives a request, a new asymmetric encryption keypair is generated. This keypair is destroyed once the request is finished in order to maintain node anonymity.