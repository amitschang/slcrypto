import("crypto");
require("rand");

public variable CRYPTO_DEFAULT_SYMETRIC="aes-256-cbc";
public variable CRYPTO_DEFAULT_DIGEST="md5";
public variable CRYPTO_DEFAULT_ROUNDS=1;

public define hexify (){
    variable data=();
    if (typeof(data)==String_Type||typeof(data)==BString_Type){
	data=bstring_to_array(data);
    }
    return strjoin(array_map(String_Type,&sprintf,"%02x",data));
}

public define unhexify (){
    variable data=();
    variable arr=bstring_to_array(strtrans(data,"\\l","\\u"));
    variable out=UChar_Type[length(arr)/2];
    variable tmp=UChar_Type[2];
    variable i,j;
    _for i (0,length(arr)-2,2){
	_for j (0,1,1){
	    if (arr[i+j] <= '9'){
		tmp[j]=arr[i+j]-'0';
	    }
	    else {
		tmp[j]=arr[i+j]-'A'+10;
	    }
	}
	out[i/2]=16*tmp[0]+tmp[1];
    }
    return array_to_bstring(out);
}

%
% Add in a higher level interface to the encryption routine which
% transparently deals with the key to password action
%
public define encrypt (){
    variable pass=();
    variable data=();
    variable key,iv;
    variable alg=qualifier("alg",CRYPTO_DEFAULT_SYMETRIC);
    variable md=qualifier("md",CRYPTO_DEFAULT_DIGEST);
    variable rounds=qualifier("rounds",CRYPTO_DEFAULT_ROUNDS);
    %
    % Make a random 8byte salt
    %
    variable salt=pack("I2",rand(2));
    (key,iv)=_genkeyiv(pass,salt,rounds,alg,md);
    %
    % Encrypt the data
    %
    variable out=_encrypt(data,key,iv,alg);
    %
    % Add in the salt indicator and salt value
    %
    out="Salted__"+salt+out;
    return out;
}

public define decrypt (){
    variable pass=();
    variable data=();
    variable key,iv;
    variable alg=qualifier("alg",CRYPTO_DEFAULT_SYMETRIC);
    variable md=qualifier("md",CRYPTO_DEFAULT_DIGEST);
    variable rounds=qualifier("rounds",CRYPTO_DEFAULT_ROUNDS);
    %
    % Get the salt from the input data, if any
    %
    variable salt="";
    variable dstart=0;
    if (data[[0:7]]=="Salted__"){
	salt=data[[8:15]];
	dstart=16;
    }
    (key,iv)=_genkeyiv(pass,salt,rounds,alg,md);
    %
    % Encrypt the data
    %
    variable out=_decrypt(data[[dstart:]],key,iv,alg);
    %
    % Add in the salt indicator and salt value
    %
    return out;
}
