#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <slang.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

static void sl_digest (void){
  SLang_BString_Type* data; /* we will give a slang string */
  unsigned char output[EVP_MAX_MD_SIZE];
  const EVP_MD *md;
  EVP_MD_CTX ctx;
  char* dtype;
  int dlen, hashlen;
  SLang_BString_Type *out;
  
  if (SLang_Num_Function_Args != 2 ||
      SLang_pop_slstring(&dtype) == -1 ){
    return;}

  md = EVP_get_digestbyname(dtype);
  if (!md){
    SLang_verror(SL_UNDEFINED_NAME,"could not find digest %s",dtype);
    SLang_free_slstring(dtype);
    return;
  }
  
  if (SLang_pop_bstring(&data) == -1 ){
    return;
  }

  unsigned char* idata = SLbstring_get_pointer (data,&dlen);

  EVP_MD_CTX_init(&ctx);
  EVP_DigestInit_ex(&ctx, md, NULL);
  EVP_DigestUpdate(&ctx, idata, dlen);
  EVP_DigestFinal(&ctx, output, &hashlen);

  out = SLbstring_create (output, hashlen);
  SLang_push_bstring(out);
  SLbstring_free(data);
  SLbstring_free(out);
}

static void sl_hmac (void){
  char *dtype;
  SLang_BString_Type *key, *data;
  unsigned char *ikey, *idata;
  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int hashlen, klen, dlen;
  SLang_BString_Type *output;
  const EVP_MD *md;

  if (SLang_Num_Function_Args != 3 ||
      SLang_pop_slstring(&dtype) == -1 ){
    return; } /* should return error there of course */

  md=EVP_get_digestbyname(dtype);
  if (!md){
    SLang_verror(SL_UNDEFINED_NAME,"could not find digest %s",dtype);
    SLang_free_slstring(dtype);
    return; }

  if (SLang_pop_bstring(&key) == -1 ||
      SLang_pop_bstring(&data) == -1 ){
    return; }

  ikey = SLbstring_get_pointer(key, &klen);
  idata = SLbstring_get_pointer(data, &dlen);
  
  HMAC(md,ikey,klen,idata,dlen,&hash,&hashlen);

  output = SLbstring_create(hash, hashlen);

  SLang_push_bstring(output);
  SLbstring_free(data);
  SLbstring_free(key);
  SLbstring_free(output);
  SLang_free_slstring(dtype);
}

static void sl_base64_encode (void){
  SLang_BString_Type* input;
  unsigned char* inbuf;
  BIO *bio, *b64;
  BUF_MEM *bptr;
  char *buff;
  int i,inlen;
  
  if (SLang_Num_Function_Args != 1 ||
      SLang_pop_bstring(&input) == -1 ){
    return; }

  inbuf = SLbstring_get_pointer(input, &inlen);

  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64,bio);
  BIO_write(b64,inbuf,inlen);
  BIO_flush(b64);
  BIO_get_mem_ptr(b64, &bptr);
  buff = (char*)malloc(bptr->length);
  memcpy(buff, bptr->data, bptr->length-1);
  buff[bptr->length-1] = 0;
  BIO_free_all(b64);
  SLang_push_string((char*)buff);
  SLbstring_free(input);
  free(buff);
}

static void sl_base64_decode (void){
  char* input, *in;
  BIO* bmem,* b64;
  SLang_BString_Type* output;
  int i, outlen;
  char nl[]="\n";
  
  if (SLang_Num_Function_Args != 1 ||
      SLang_pop_slstring(&in) == -1 ){
    return; }

  /* For some reason, the input is required to have a newline at the
     end, doesn't matter how many, so tack one on here*/
  input = SLang_concat_slstrings(in,nl);
  SLang_free_slstring(in);

  unsigned char* buff = (char*)malloc((int)strlen(input)+1);
  memset(buff,0,(int)strlen(input));

  b64  = BIO_new(BIO_f_base64());
  bmem = BIO_new_mem_buf(input,(int)strlen(input));
  bmem = BIO_push(b64,bmem);
  outlen = BIO_read(bmem,buff,(int)strlen(input));
  BIO_free_all(bmem);

  output = SLbstring_create(buff, outlen);

  SLang_push_bstring(output);
  SLang_free_slstring(input);
  SLbstring_free(output);
  free(buff);
}

static void sl_encrypt (void){
  /* input types */
  char *ctype;
  unsigned char *outbuf, *iiv, *ikey, *idata;
  SLang_BString_Type *iv, *key, *data;
  /* internal types */
  EVP_CIPHER_CTX ctx;
  const EVP_CIPHER *cipher;
  int outlen, tmplen, dlen, i;
  /* output types */
  SLang_BString_Type *output;

  if (SLang_Num_Function_Args != 4 ||
      SLang_pop_slstring(&ctype) == -1 ){
    return; }

  cipher = EVP_get_cipherbyname(ctype);
  if (!cipher){
    SLang_verror(SL_UNDEFINED_NAME,"could not find cipher %s",ctype);
    return;
  }
  
  if (SLang_pop_bstring(&iv) == -1 ||
      SLang_pop_bstring(&key) == -1 ||
      SLang_pop_bstring(&data) == -1 ){
    return; }

  iiv = SLbstring_get_pointer (iv,&i);
  ikey = SLbstring_get_pointer (key,&i);
  idata = SLbstring_get_pointer (data,&dlen);

  outbuf = (char*)malloc(dlen+EVP_CIPHER_block_size(cipher));

  EVP_CIPHER_CTX_init(&ctx);
  EVP_EncryptInit_ex(&ctx, cipher, NULL, ikey, iiv);
  
  if (!EVP_EncryptUpdate(&ctx, outbuf, &outlen, idata, dlen)){
    return; /*emit an error here*/
  }
  if (!EVP_EncryptFinal(&ctx, outbuf + outlen, &tmplen)){
    return; /*emit an error here*/
  }
  outlen+=tmplen;

  output = SLbstring_create (outbuf, outlen);
  
  SLang_push_bstring(output);
  SLbstring_free(output);
  SLbstring_free(data);
  SLbstring_free(key);
  SLbstring_free(iv);
  free(outbuf);
}

static void sl_decrypt (void){
  /* input types */
  char *ctype;
  unsigned char *outbuf, *iiv, *ikey, *idata;
  SLang_BString_Type *iv, *key, *data;
  /* internal types */
  EVP_CIPHER_CTX ctx;
  const EVP_CIPHER *cipher;
  int outlen, tmplen, dlen, i;
  /* output types */
  SLang_BString_Type *output;

  if (SLang_Num_Function_Args != 4 ||
      SLang_pop_slstring(&ctype) == -1 ){
    return; }

  cipher = EVP_get_cipherbyname(ctype);
  if (!cipher){
    SLang_verror(SL_UNDEFINED_NAME,"could not find cipher %s",ctype);
    return;
  }
  
  if (SLang_pop_bstring(&iv) == -1 ||
      SLang_pop_bstring(&key) == -1 ||
      SLang_pop_bstring(&data) == -1 ){
    return; }

  iiv = SLbstring_get_pointer (iv,&i);
  ikey = SLbstring_get_pointer (key,&i);
  idata = SLbstring_get_pointer (data,&dlen);

  outbuf = (char*)malloc(dlen+EVP_CIPHER_block_size(cipher));

  EVP_CIPHER_CTX_init(&ctx);
  EVP_DecryptInit_ex(&ctx, cipher, NULL, ikey, iiv);
  
  if (!EVP_DecryptUpdate(&ctx, outbuf, &outlen, idata, dlen)){
    return; /*emit an error here*/
  }
  if (!EVP_DecryptFinal(&ctx, outbuf + outlen, &tmplen)){
    return; /*emit an error here*/
  }
  outlen+=tmplen;

  output = SLbstring_create (outbuf, outlen);
  
  SLang_push_bstring(output);
  SLbstring_free(output);
  SLbstring_free(data);
  SLbstring_free(key);
  SLbstring_free(iv);
  free(outbuf);
}

static void sl_generate_key (void){
  char* pass, *ctype, *dtype;
  SLang_BString_Type* salta;
  const EVP_CIPHER *cipher;
  const EVP_MD *md;
  unsigned char *salt;
  unsigned char *key;
  unsigned char *iv;
  SLang_BString_Type* outkey, *outiv;
  int count,i,keylen,ivlen,saltlen;

  if (SLang_Num_Function_Args != 5 ||
      SLang_pop_slstring(&dtype) == -1 ||
      SLang_pop_slstring(&ctype) == -1 ){
    return; }
  
  cipher = EVP_get_cipherbyname(ctype);
  if (!cipher){
    SLang_verror(SL_UNDEFINED_NAME,"could not find cipher %s",ctype);
    SLang_free_slstring(ctype);
    return;
  }
  md = EVP_get_digestbyname(dtype);
  if (!md){
    SLang_verror(SL_UNDEFINED_NAME,"could not find digest %s",dtype);
    SLang_free_slstring(ctype);
    SLang_free_slstring(dtype);
    return;
  }

  if (SLang_pop_integer(&count) == -1 ||
      SLang_pop_bstring(&salta) == -1 ||
      SLang_pop_slstring(&pass) == -1 ){
    return; }

  keylen = EVP_CIPHER_key_length(cipher);
  ivlen  = EVP_CIPHER_iv_length(cipher);
  key = (char*)malloc(keylen);
  iv  = (char*)malloc(ivlen);

  salt = SLbstring_get_pointer(salta,&saltlen);
  
  if (saltlen==0){
    salt=NULL;
  }
  else if (saltlen!=8){
    SLang_verror(SL_USAGE_ERROR,"Salt must not exceed 8 bytes");
    SLbstring_free(salta);
    SLang_free_slstring(pass);
    SLang_free_slstring(ctype);
    SLang_free_slstring(dtype);
    return;
  }
    
  
  EVP_BytesToKey(cipher,md,salt,pass,(int)strlen(pass),count,key,iv);

  outkey = SLbstring_create(key, keylen);
  outiv  = SLbstring_create(iv, ivlen);

  SLang_push_bstring(outkey);
  SLang_push_bstring(outiv);
  SLbstring_free(salta);
  SLbstring_free(outkey);
  SLbstring_free(outiv);
  SLang_free_slstring(pass);
  SLang_free_slstring(ctype);
  SLang_free_slstring(dtype);
  free(key);free(iv);
}

#define SSL_PROTO_SSL2 0
#define SSL_PROTO_SSL3 1
#define SSL_PROTO_TLS1 2
#define SSL_PROTO_SSL23 3
#define SSL_PROTO_ANY 4

static int SLssl_Type_Id = -1;
typedef struct
{
  void *ssl;
  int is_server;
}
SLssl_Type;


static void sl_ssl_server (void){
  // create an ssl object and return the memory managed type back to
  // SLang. It needs the file descriptor of the object upon which
  // communication will occur, and the protocol to use
  //
  // this is the server, so it also needs the certfile and private key
  SSL_CTX *ctx;
  SSL *ssl;
  int proto, pkey_type, cert_type, fd;
  SLang_MMT_Type *sslmmt;
  SLFile_FD_Type *slfd;
  char *pkey, *cert;
  SLssl_Type *slssl;

  if (SLang_pop_integer(&proto) == -1 ||
      SLang_pop_slstring(&pkey) == -1 ||
      SLang_pop_integer(&pkey_type) == -1 ||
      SLang_pop_slstring(&cert) == -1 ||
      SLang_pop_integer(&cert_type) == -1 ||
      SLfile_pop_fd(&slfd) == -1){
    return;
  }
  
  if (proto==SSL_PROTO_SSL2)
    ctx = SSL_CTX_new(SSLv23_server_method());
  else if (proto==SSL_PROTO_SSL3)
    ctx = SSL_CTX_new(SSLv3_server_method());
  else if (proto==SSL_PROTO_TLS1)
    ctx = SSL_CTX_new(TLSv1_server_method());
  else if (proto==SSL_PROTO_ANY)
    ctx = SSL_CTX_new(SSLv23_server_method());

  // now add the cert file an private key
  SSL_CTX_use_certificate_file(ctx,cert,cert_type);
  SSL_CTX_use_PrivateKey_file(ctx,pkey,pkey_type);
  SLang_free_slstring(pkey);
  SLang_free_slstring(cert);
  if (1!=SSL_CTX_check_private_key(ctx)){
    SLang_verror(0,"Certificate and private keys do not match");
    return;
  }

  // create the ssl object
  ssl = SSL_new(ctx);
  
  // set the file descriptor for input/output
  SLfile_get_fd(slfd,&fd);
  if (0==SSL_set_fd(ssl,fd))
    return;

  fprintf(stderr,"Set server socket fd to %d\n",fd);

  slssl = (SLssl_Type *)malloc(sizeof(SLssl_Type));
  slssl->ssl = (void *) ssl;
  slssl->is_server = 1;

  sslmmt = SLang_create_mmt(SLssl_Type_Id, (VOID_STAR) slssl);

  if (0==SLang_push_mmt(sslmmt))
    return;
  
  SLang_free_mmt(sslmmt);
}

static void sl_ssl_client (void){
  // create an ssl object and return the memory managed type back to
  // SLang. It needs the file descriptor of the object upon which
  // communication will occur, and the protocol to use
  //
  // this is the client, no certs by default
  SSL_CTX *ctx;
  SSL *ssl;
  int proto;
  SLFile_FD_Type *slfd;
  int fd;
  SLang_MMT_Type *mmt, *sslmmt;
  SLssl_Type *slssl;

  if (SLang_pop_integer(&proto) == -1 ||
      SLfile_pop_fd(&slfd) == -1){
    return;
  }

  SLfile_get_fd(slfd,&fd);
  SLfile_free_fd(slfd);
  
  if (proto==SSL_PROTO_SSL2)
    ctx = SSL_CTX_new(SSLv23_client_method());
  else if (proto==SSL_PROTO_SSL3)
    ctx = SSL_CTX_new(SSLv3_client_method());
  else if (proto==SSL_PROTO_TLS1)
    ctx = SSL_CTX_new(TLSv1_client_method());
  else if (proto==SSL_PROTO_ANY)
    ctx = SSL_CTX_new(SSLv23_client_method());

  // create the ssl object
  ssl = SSL_new(ctx);
  
  // set the file descriptor for input/output
  if (0==SSL_set_fd(ssl,fd)){
    return;
  }
  fprintf(stderr,"Set client socket fd to %d\n",fd);

  slssl = (SLssl_Type *)malloc(sizeof(SLssl_Type));
  slssl->ssl = (void *) ssl;
  slssl->is_server = 0;

  sslmmt = SLang_create_mmt(SLssl_Type_Id, (VOID_STAR) slssl);

  if (0==SLang_push_mmt(sslmmt))
    return;
}

static void sl_ssl_handshake (void){
  SLssl_Type *ssl;
  SLang_MMT_Type *sslmmt;
  int r;
  
  if (NULL==(sslmmt=SLang_pop_mmt(SLssl_Type_Id)))
    return;

  ssl=(SLssl_Type *)SLang_object_from_mmt(sslmmt);

  if (ssl->is_server==1)
    r=SSL_accept((SSL *)ssl->ssl);
  else
    r=SSL_connect((SSL *)ssl->ssl);

  if (r==1)
    SLang_push_integer(r);
  else
    SLang_verror(r,"SSL handshake returned %d (error code %d)",r,
		 SSL_get_error((SSL *)ssl->ssl,r));
}

static void sl_ssl_verify(void){
  SLssl_Type *ssl;
  SLang_MMT_Type *sslmmt;
  X509 *cert;

  if (NULL==(sslmmt=SLang_pop_mmt(SLssl_Type_Id)))
    return;

  ssl=(SLssl_Type *)SLang_object_from_mmt(sslmmt);

  cert=SSL_get_peer_certificate((SSL *)ssl->ssl);
  if (cert==NULL)
    SLang_push_integer(0);
  else
    SLang_push_integer(SSL_get_verify_result((SSL *)ssl->ssl));

  X509_free(cert);
}

static void sl_ssl_get_cert(void){
  SLssl_Type *ssl;
  SLang_MMT_Type *sslmmt;
  X509 *cert;
  int len;
  unsigned char *buf;
  SLang_BString_Type *certout;

  if (NULL==(sslmmt=SLang_pop_mmt(SLssl_Type_Id)))
    return;

  ssl=(SLssl_Type *)SLang_object_from_mmt(sslmmt);

  cert=SSL_get_peer_certificate((SSL *)ssl->ssl);

  buf = NULL;
  
  len = i2d_X509(cert, &buf);

  if (len>0){
    certout=SLbstring_create(buf,len);
    SLang_push_bstring(certout);
    SLbstring_free(certout);
  }
  X509_free(cert);
}

static void sl_ssl_write(void){
  SLssl_Type *ssl;
  SLang_MMT_Type *sslmmt;
  SLang_BString_Type *data;
  int r, dlen;
  
  if (SLang_pop_bstring(&data)==-1 ||
      NULL==(sslmmt=SLang_pop_mmt(SLssl_Type_Id)))
    return;

  ssl=(SLssl_Type *)SLang_object_from_mmt(sslmmt);

  const void *idata = SLbstring_get_pointer(data,&dlen);

  r=SSL_write((SSL *)ssl->ssl,idata,dlen);

  if (r>=0)
    SLang_push_integer(r);
  else
    SLang_verror(r,"SSL write returned error code %d",
		 SSL_get_error((SSL *)ssl->ssl,r));

  SLbstring_free(data);
}

static void sl_ssl_read(void){
  SLssl_Type *ssl;
  SLang_MMT_Type *sslmmt;
  SLang_Ref_Type *buff;
  void *ibuff;
  SLang_BString_Type *data;
  int r, rlen;
  
  if (SLang_pop_integer(&rlen)==-1 ||
      SLang_pop_ref(&buff)==-1 ||
      NULL==(sslmmt=SLang_pop_mmt(SLssl_Type_Id)))
    return;

  ssl=(SLssl_Type *)SLang_object_from_mmt(sslmmt);

  ibuff=(void *)malloc(rlen);

  r=SSL_read((SSL *)ssl->ssl,ibuff,rlen);

  data=SLbstring_create((unsigned char *)ibuff,r);

  SLang_assign_to_ref(buff, SLANG_BSTRING_TYPE, (VOID_STAR)&data);

  if (r>=0)
    SLang_push_integer(r);
  else
    SLang_verror(r,"SSL read returned error code %d",
		 SSL_get_error((SSL *)ssl->ssl,r));

  SLang_free_ref(buff);
}

static void sl_destroy_ssl (SLtype type, VOID_STAR f){
  /* SLssl_Type *ssl; */
  /* ssl=(SLssl_Type *)*f; */
  /* SSL_free((SSL *)f->ssl); */
}

static int register_classes (void)
{
  SLang_Class_Type *cl;

  if (SLssl_Type_Id != -1)
    return 0;

  if (NULL == (cl = SLclass_allocate_class ("SLssl_Type")))
    return -1;

  (void) SLclass_set_destroy_function (cl, sl_destroy_ssl);

  if (-1 == SLclass_register_class (cl, SLANG_VOID_TYPE,
                                    sizeof (SLssl_Type),
                                    SLANG_CLASS_TYPE_MMT))
    return -1;

  SLssl_Type_Id = SLclass_get_class_id (cl);

  return 0;
}

static SLang_Intrin_Fun_Type Module_Intrinsics [] = {
  MAKE_INTRINSIC_0("digest",sl_digest,SLANG_VOID_TYPE),
  MAKE_INTRINSIC_0("hmac",sl_hmac,SLANG_VOID_TYPE),
  MAKE_INTRINSIC_0("_encrypt",sl_encrypt,SLANG_VOID_TYPE),
  MAKE_INTRINSIC_0("_decrypt",sl_decrypt,SLANG_VOID_TYPE),
  MAKE_INTRINSIC_0("_genkeyiv",sl_generate_key,SLANG_VOID_TYPE),
  MAKE_INTRINSIC_0("base64_encode",sl_base64_encode,SLANG_VOID_TYPE),
  MAKE_INTRINSIC_0("base64_decode",sl_base64_decode,SLANG_VOID_TYPE),
  MAKE_INTRINSIC_0("ssl_server",sl_ssl_server,SLANG_VOID_TYPE),
  MAKE_INTRINSIC_0("ssl_client",sl_ssl_client,SLANG_VOID_TYPE),
  MAKE_INTRINSIC_0("ssl_handshake",sl_ssl_handshake,SLANG_VOID_TYPE),
  MAKE_INTRINSIC_0("ssl_read",sl_ssl_read,SLANG_VOID_TYPE),
  MAKE_INTRINSIC_0("ssl_write",sl_ssl_write,SLANG_VOID_TYPE),
  MAKE_INTRINSIC_0("ssl_verify",sl_ssl_verify,SLANG_VOID_TYPE),
  MAKE_INTRINSIC_0("ssl_cert",sl_ssl_get_cert,SLANG_VOID_TYPE),
  SLANG_END_INTRIN_FUN_TABLE
};

static SLang_Intrin_Var_Type Module_Variables [] =
  {
    MAKE_VARIABLE("SSL_FILETYPE_ASN1",2, SLANG_INT_TYPE, 0),
    MAKE_VARIABLE("SSL_FILETYPE_PEM",1, SLANG_INT_TYPE, 0),
    SLANG_END_INTRIN_VAR_TABLE
  };

SLANG_MODULE(crypto);
int init_crypto_module_ns (char *ns_name){
  SLang_NameSpace_Type *ns = SLns_create_namespace(ns_name);
  if (ns == NULL)
    return -1;
  
  if (-1 == register_classes ())
    return -1;
  
  if (
      (-1 == SLns_add_intrin_fun_table (ns, Module_Intrinsics, NULL)) ||
      (-1 == SLns_add_intrin_var_table (ns, Module_Variables, NULL))
      )
    return -1;
  
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  
  return 0;
}
