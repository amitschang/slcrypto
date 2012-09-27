set_import_module_path(".");
require("crypto");
require("socket");

variable s=socket(AF_INET,SOCK_STREAM,0);
connect(s,__argv[1],atoi(__argv[2]));
variable ssl=ssl_client(s,4);
variable ret=ssl_handshake(ssl);
variable verify=ssl_verify(ssl);
variable cert=ssl_cert(ssl);
print(base64_encode(cert));
vmessage("client handshake complete, returned %d, return value from verify: %d",ret,verify);
variable msg;
while (1){
      ()=fgets(&msg,stdin);
      ssl_write(ssl,msg);
      ssl_read(ssl,&msg,1024);
      print(msg);
}


