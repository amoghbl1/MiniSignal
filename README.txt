Requirements to run the client and server.
* google protobuf for python and protoc.
* make
* python 2.7.*
* Run `make protobuf` before to generate necessary python classes.
* server.priv to run server and server.pub to run client. (Long term key associated to the server)
  - This server key uses curve SECP384R1 for encryption/decryption, any keypair that satisfies this property could be used, given it is in the PEM format.
  - A Python file `key_generator.py` is used to generate such a keypair: `./key_generator.py -g server`.

ChatServer:
* Run `./ChatServer.py -h` for help page.
* Binds automatically to 127.0.0.1:4590. Both IP and Port can be configured at launch.
* Registers users that connect to it.
* Serves a list of connected users if it receives a valid request.
* All communications sent over the network are serialized using protobuf.
* Multi threaded and can handle multiple requests in parallel.
* Implements acknowledgements for all requirements to make UDP slightly reliable.

ChatClient:
* Run `./ChatClient.py -h` for help page.
* Registers automatically to server 127.0.0.1:4590. Both IP and Port can be passed as CLI flags.
* Handles sending messages to users registered with the server.
* Implements fetching list of connected users with the `list` command.
* Implements sending a message to a connected user and handles the case if no user exists.
Chat command line interface implements the following commands: help list exit msg/send signup signin/login signout/logout
* help: prints this help page.
* list: lists the users connected to the server at this point of time.
* exit: exits the application.
* msg/send: <username required> sends a message to the username supplied, given the user is logged into the server.
* logout/signout: signs the user out of the server logged into.
* connect: <server ip> <server port> connect to the server on the ip port. Does not log in.
* login/signin: <username> <password> login with a username password.
* signup: <username> <password> registers a user associated to the password supplied on the server connected to.

Registered users:
* The list of registered users: "user":"iiit123", "u1":"u1", "u2":"u2", "u3":"u3"
