#include <unistd.h> 
#include <stdio.h> 
#include <sys/socket.h> 
#include <stdlib.h> 
#include <netinet/in.h> 
#include <string.h> 
#include<iostream>
#include "crypto++/cryptlib.h"
#include "crypto++/dh.h"
#include "crypto++/dh2.h"
#include "crypto++/osrng.h"
#include "crypto++/integer.h"
#include "crypto++/nbtheory.h"
#include "crypto++/hex.h"
#include "crypto++/filters.h"
#include "crypto++/des.h"
#include "crypto++/modes.h"
#include "crypto++/secblock.h"
#include "crypto++/dh.h"
#include "crypto++/dh2.h"
using namespace std;
using namespace CryptoPP;
#define PORT 8080
#define BUFF_SIZE 64
const bool tval = true, fval = false;

Integer receive_Integer(int fd)
{
	Integer I;
	int in;
	bool bit;
	read(fd, &in, sizeof(in));
	while(in--)
	{
		read(fd, &bit, sizeof(bit));
		if(bit)
			I += Integer::Power2(in);
	}
	return I;
}

void send_Integer(Integer &I, int fd)
{
	int bc = I.BitCount();
	
	send(fd , &bc , sizeof(bc) , 0);
	while(bc--)
	{
		if(I.GetBit(bc))
			send(fd, &tval, sizeof(tval), 0);
		else
			send(fd, &fval, sizeof(fval), 0);
	}
}

void DES_Process(char *keyString, byte *block, size_t length, CryptoPP::CipherDir direction)
{ 
    byte key[DES_EDE2::KEYLENGTH];
    memcpy(key, keyString, DES_EDE2::KEYLENGTH);
    BlockTransformation *t = NULL;

    if(direction == ENCRYPTION)
        t = new DES_EDE2_Encryption(key, DES_EDE2::KEYLENGTH);
    else
        t = new DES_EDE2_Decryption(key, DES_EDE2::KEYLENGTH);

    int steps = length / t->BlockSize();
    if(length % t->BlockSize())
        ++steps;
    for(int i=0; i<steps; i++){
        int offset = i * t->BlockSize();
        t->ProcessBlock(block + offset);
    }

    delete t;
}

SecByteBlock Int2Block(Integer x)
{
	SecByteBlock bytes;
    size_t encodedSize = x.MinEncodedSize(Integer::UNSIGNED);
    bytes.resize(encodedSize);
    x.Encode(bytes.BytePtr(), encodedSize, Integer::UNSIGNED);
    return bytes;
}

void *DH_auth(void *ptr)
{
	AutoSeededRandomPool rnd1;
	int fd = *(int *)ptr;
	
	Integer p1 = receive_Integer(fd);
	cout<<"received der integer p1 "<<p1<<endl;

	Integer g1 = receive_Integer(fd);
	cout<<"received der integer g1 "<<g1<<endl;
	Integer pubkC1 = receive_Integer(fd);
	cout<<"received der pubkey "<<pubkC1<<endl;
	DH dhS1 = CryptoPP::DH(p1, g1);

	SecByteBlock privKeyS1, pubKeyS1;
	privKeyS1 = SecByteBlock(dhS1.PrivateKeyLength());
    pubKeyS1 = SecByteBlock(dhS1.PublicKeyLength());
    dhS1.GenerateKeyPair(rnd1, privKeyS1, pubKeyS1);

    Integer pubk1(pubKeyS1, pubKeyS1.size());
	Integer privk1(privKeyS1, privKeyS1.size());
	send_Integer(pubk1, fd);

	cout<<"pubkey "<<pubk1<<endl;
    cout<<"privkey "<<privk1<<endl;

    Integer shared_key1 = ModularExponentiation(pubkC1, privk1, p1);
    cout<<"shared key "<<shared_key1<<endl;


    SecByteBlock Key1 = Int2Block(shared_key1);
    char enkey1[sizeof(Key1)];
    memcpy(enkey1, Key1, sizeof(Key1));



    AutoSeededRandomPool rnd2;	
	Integer p2 = receive_Integer(fd);
	cout<<"received der integer p2 "<<p2<<endl;

	Integer g2 = receive_Integer(fd);
	cout<<"received der integer g2 "<<g2<<endl;
	Integer pubkC2 = receive_Integer(fd);
	cout<<"received der pubkey "<<pubkC2<<endl;
	DH dhS2 = CryptoPP::DH(p2, g2);

	SecByteBlock privKeyS2, pubKeyS2;
	privKeyS2 = SecByteBlock(dhS2.PrivateKeyLength());
    pubKeyS2 = SecByteBlock(dhS2.PublicKeyLength());
    dhS2.GenerateKeyPair(rnd2, privKeyS2, pubKeyS2);

    Integer pubk2(pubKeyS2, pubKeyS2.size());
	Integer privk2(privKeyS2, privKeyS2.size());
	send_Integer(pubk2, fd);

	cout<<"pubkey "<<pubk2<<endl;
    cout<<"privkey "<<privk2<<endl;

    Integer shared_key2 = ModularExponentiation(pubkC2, privk2, p2);
    cout<<"shared key "<<shared_key2<<endl;


    SecByteBlock Key2 = Int2Block(shared_key2);
    char enkey2[sizeof(Key2)];
    memcpy(enkey2, Key2, sizeof(Key2));


    AutoSeededRandomPool rnd3;	
	Integer p3 = receive_Integer(fd);
	cout<<"received der integer p3 "<<p3<<endl;

	Integer g3 = receive_Integer(fd);
	cout<<"received der integer g3 "<<g3<<endl;
	Integer pubkC3 = receive_Integer(fd);
	cout<<"received der pubkey "<<pubkC3<<endl;
	DH dhS3 = CryptoPP::DH(p3, g3);

	SecByteBlock privKeyS3, pubKeyS3;
	privKeyS3 = SecByteBlock(dhS3.PrivateKeyLength());
    pubKeyS3 = SecByteBlock(dhS3.PublicKeyLength());
    dhS3.GenerateKeyPair(rnd3, privKeyS3, pubKeyS3);

    Integer pubk3(pubKeyS3, pubKeyS3.size());
	Integer privk3(privKeyS3, privKeyS3.size());
	send_Integer(pubk3, fd);

	cout<<"pubkey "<<pubk3<<endl;
    cout<<"privkey "<<privk3<<endl;

    Integer shared_key3 = ModularExponentiation(pubkC3, privk3, p3);
    cout<<"shared key "<<shared_key3<<endl;


    SecByteBlock Key3 = Int2Block(shared_key3);
    char enkey3[sizeof(Key3)];
    memcpy(enkey3, Key3, sizeof(Key3));

    char buffer[BUFF_SIZE] = "ricknmorty.mkv";
    byte block[1024] ;
    

    FILE *fp = fopen ( buffer, "rb" );
	if(fp==NULL)
	{
		cout<<"cant open file\n";
		pthread_exit(NULL);
	}
	fseek(fp, 0, SEEK_END);
	int size = ftell(fp);                       //calculate filesize
	rewind(fp);
	cout<<"size of file is "<<size<<endl;
	send(fd, &size, sizeof(size), 0);        //textll the size to other peer
	cout<<"sent filesize "<<size<<endl;
	ssize_t n;
	memset(block, '\0', 1024);
	// memset(buffer, '\0', sizeof(buffer));
	while ((n=fread( block , sizeof(char) , 1024, fp ) ) > 0)
	{
	    DES_Process(enkey1, block, n, CryptoPP::ENCRYPTION);
	    DES_Process(enkey2, block, 1024, CryptoPP::DECRYPTION);
	    DES_Process(enkey3, block, 1024, CryptoPP::ENCRYPTION);
		send(fd, block, 1024, 0);
		// cout<<"decrypted text :"<<block<<endl;
   	 	// memset ( buffer , '\0', BUFF_SIZE);
   	 	memset(block, '\0', 1024);
	}

	cout<<"sent file\n";
	close(fd);
	fclose(fp);
	pthread_exit(NULL);
}

int main(int argc, char const *argv[]) 
{ 
	int server_fd, valread; 
	struct sockaddr_in address; 
	int opt = 1; 
	int addrlen = sizeof(address); 
	char buffer[1024] = {0}; 
	char *hello = "Hello from server"; 
	
	// Creating socket file descriptor 
	if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) 
	{ 
		perror("socket failed"); 
		exit(EXIT_FAILURE); 
	} 
	
	// Forcefully attaching socket to the port 8080 
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, 
												&opt, sizeof(opt))) 
	{ 
		perror("setsockopt"); 
		exit(EXIT_FAILURE); 
	} 
	address.sin_family = AF_INET; 
	address.sin_addr.s_addr = INADDR_ANY; 
	address.sin_port = htons( PORT ); 
	
	// Forcefully attaching socket to the port 8080 
	if (bind(server_fd, (struct sockaddr *)&address, 
								sizeof(address))<0) 
	{ 
		perror("bind failed"); 
		exit(EXIT_FAILURE); 
	} 
	if (listen(server_fd, 3) < 0) 
	{ 
		perror("listen"); 
		exit(EXIT_FAILURE); 
	} 
	
	pthread_t threads[50];
	int counter=0;
	while(1)
	{
		int new_socket;
		cout<<"waiting for incoming request\n";
		if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen))<0) 
		{ 
			perror("accept"); 
			exit(EXIT_FAILURE); 
		}
		
		pthread_create(&threads[counter++], NULL, DH_auth, (void *)&new_socket);
	}
} 
