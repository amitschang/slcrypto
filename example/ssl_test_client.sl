set_import_module_path(".");
require("crypto");
require("socket");

variable s=socket(AF_INET,SOCK_STREAM,0);
connect(s,__argv[1],atoi(__argv[2]));
variable cli=ssl_client(SSL_PROTO_ANY,NULL,"/usr/lib/ssl/certs/");
variable ssl=ssl_connect(cli,s);
% variable ssl=ssl_connect(ssl_client(SSL_PROTO_ANY),s);
variable ret=ssl_handshake(ssl);
variable verify=ssl_verify(ssl);
variable certs=ssl_cert(ssl);
variable i;
_for i (0,length(certs)-1,1){
    fprintf(stdout,base64_encode(certs[i]));
}
vmessage("client handshake complete, returned %d, return value from verify: %d",ret,verify);
variable msg;
while (1){
      ()=fgets(&msg,stdin);
      ssl_write(ssl,msg);
      ssl_read(ssl,&msg,1024);
      print(msg);
}


