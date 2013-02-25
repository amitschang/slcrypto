set_import_module_path(".");
require("crypto");
require("socket");

variable serv=ssl_server(SSL_PROTO_ANY,"/home/arikm/.ssh/cert.pem","/home/arikm/private/id_rsa");
variable host,port;
variable s=socket(AF_INET,SOCK_STREAM,0);
bind(s,"localhost",atoi(__argv[1]));
listen(s,1);
variable c=accept(s,&host,&port);
vmessage("got connection from %s:%d",host,port);
variable ssl=ssl_connect(serv,c);
variable ret=ssl_handshake(ssl);
vmessage("server handshake complete, returned %d",ret);
variable buf;
while (1){
      if (not ssl_read(ssl,&buf,1024))
      	 break;
      vmessage("%s",strtrim(buf));
}