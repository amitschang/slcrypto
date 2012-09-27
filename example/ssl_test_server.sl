set_import_module_path(".");
require("crypto");
require("socket");

variable host,port;
variable s=socket(AF_INET,SOCK_STREAM,0);
bind(s,"localhost",atoi(__argv[1]));
listen(s,1);
variable c=accept(s,&host,&port);
vmessage("got connection from %s:%d",host,port);
variable ssl=ssl_server(c,1,"/home/arikm/.ssh/cert.pem",1,"/home/arikm/private/id_rsa",4);
variable ret=ssl_handshake(ssl);
vmessage("server handshake complete, returned %d",ret);
variable buf;
while (1){
      if (not ssl_read(ssl,&buf,1024))
      	 break;
      vmessage("%s",strtrim(buf));
}