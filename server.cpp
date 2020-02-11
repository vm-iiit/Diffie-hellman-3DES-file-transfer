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

#define PORT 9876
#define BUFF_SIZE 1024
const bool tval = true, fval = false;
const int ten=10, twenty=20, thirty=30, forty=40, fifty=50, na=0;
bool bsync;

struct PubKey{
	Integer large_prime;
	Integer primitive_root;
	Integer pubkey;
};

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

void receive_Pubkey(struct PubKey &spk, int fd)
{
	spk.large_prime = receive_Integer(fd);
	spk.primitive_root = receive_Integer(fd);
	spk.pubkey = receive_Integer(fd);
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

struct enckeys{
	char K1[BUFF_SIZE];
	char K2[BUFF_SIZE];
	char K3[BUFF_SIZE];
};

typedef struct enckeys Keyset;

char **Diffie_Hellman(int fd)
{
	char **Karr = (char **)malloc(sizeof(char*)*3);

	AutoSeededRandomPool rnd1;	
	Integer p1 = receive_Integer(fd);
	cout<<"received Large prime 1 : " << p1 << '\n';

	Integer g1 = receive_Integer(fd);
	cout<<"received Primitive root 1 : " << g1 << '\n';
	Integer pubkC1 = receive_Integer(fd);
	cout<<"received pubkey1 from client "<<pubkC1<<endl;
	DH dhS1 = CryptoPP::DH(p1, g1);

	SecByteBlock privKeyS1, pubKeyS1;
	privKeyS1 = SecByteBlock(dhS1.PrivateKeyLength());
    pubKeyS1 = SecByteBlock(dhS1.PublicKeyLength());
    dhS1.GenerateKeyPair(rnd1, privKeyS1, pubKeyS1);

    Integer pubk1(pubKeyS1, pubKeyS1.size());
	Integer privk1(privKeyS1, privKeyS1.size());
	send_Integer(pubk1, fd);

	cout<<"pubkey 1 : "<<pubk1<<endl;
    cout<<"privkey 1 :"<<privk1<<endl;

    Integer shared_key1 = ModularExponentiation(pubkC1, privk1, p1);
    cout<<"shared key 1 :"<<shared_key1<<endl<<endl;

    SecByteBlock Key1 = Int2Block(shared_key1);
    Karr[0] = (char *)malloc(sizeof(shared_key1));
    memcpy(Karr[0], Key1, sizeof(Key1));


    AutoSeededRandomPool rnd2;	
	Integer p2 = receive_Integer(fd);
	cout<<"received Large prime 2 "<<p2<<endl;

	Integer g2 = receive_Integer(fd);
	cout<<"received Primitive root 2 "<<g2<<endl;
	Integer pubkC2 = receive_Integer(fd);
	cout<<"received pubkey2 from client "<<pubkC2<<endl;
	DH dhS2 = CryptoPP::DH(p2, g2);

	SecByteBlock privKeyS2, pubKeyS2;
	privKeyS2 = SecByteBlock(dhS2.PrivateKeyLength());
    pubKeyS2 = SecByteBlock(dhS2.PublicKeyLength());
    dhS2.GenerateKeyPair(rnd2, privKeyS2, pubKeyS2);

    Integer pubk2(pubKeyS2, pubKeyS2.size());
	Integer privk2(privKeyS2, privKeyS2.size());
	send_Integer(pubk2, fd);

	cout<<"pubkey 2 : "<<pubk2<<endl;
    cout<<"privkey 2 : "<<privk2<<endl;

    Integer shared_key2 = ModularExponentiation(pubkC2, privk2, p2);
    cout<<"shared key 2 :"<<shared_key2<<endl<<endl;


    SecByteBlock Key2 = Int2Block(shared_key2);
    Karr[1] = (char *)malloc(sizeof(shared_key2));
    memcpy(Karr[1], Key2, sizeof(Key2));

    AutoSeededRandomPool rnd3;	
	Integer p3 = receive_Integer(fd);
	cout<<"received Large prime 3 "<<p3<<endl;

	Integer g3 = receive_Integer(fd);
	cout<<"received Primitive root 3 "<<g3<<endl;
	Integer pubkC3 = receive_Integer(fd);
	cout<<"received pubkey3 from client "<<pubkC3<<endl;
	DH dhS3 = CryptoPP::DH(p3, g3);

	SecByteBlock privKeyS3, pubKeyS3;
	privKeyS3 = SecByteBlock(dhS3.PrivateKeyLength());
    pubKeyS3 = SecByteBlock(dhS3.PublicKeyLength());
    dhS3.GenerateKeyPair(rnd3, privKeyS3, pubKeyS3);

    Integer pubk3(pubKeyS3, pubKeyS3.size());
	Integer privk3(privKeyS3, privKeyS3.size());
	send_Integer(pubk3, fd);

	cout<<"pubkey 3 : "<<pubk3<<endl;
    cout<<"privkey 3 : "<<privk3<<endl;

    Integer shared_key3 = ModularExponentiation(pubkC3, privk3, p3);
    cout<<"shared key 3 : "<<shared_key3<<endl<<endl;


    SecByteBlock Key3 = Int2Block(shared_key3);
    Karr[2] = (char *)malloc(sizeof(shared_key3));
    memcpy(Karr[2], Key3, sizeof(Key3));
    cout<<"\n3 Keys obtained\n";
    return Karr;
}

void send_file(char *filename, int fd, char **Karr)
{
	
    char buffer[BUFF_SIZE];
    byte block[BUFF_SIZE] ;
    
    FILE *fp = fopen(filename, "rb");
	fseek(fp, 0, SEEK_END);
	long long int size = ftell(fp);
	ssize_t n;
	rewind(fp);
	cout<<"size of file is "<<size<<endl;
	send(fd, &size, sizeof(size), 0);        
	memset(block, '\0', BUFF_SIZE);
	int lc=0;
	while (size > 0)
	{	
		recv(fd, &bsync, sizeof(bsync), 0);
		n=fread( block , sizeof(char) , BUFF_SIZE, fp );
		send(fd, &n, sizeof(n), 0);
	    DES_Process(Karr[0], block, n, CryptoPP::ENCRYPTION);
	    DES_Process(Karr[1], block, BUFF_SIZE, CryptoPP::DECRYPTION);
	    DES_Process(Karr[2], block, BUFF_SIZE, CryptoPP::ENCRYPTION);
		send(fd, block, BUFF_SIZE*sizeof(byte), 0);
   	 	memset(block, '\0', BUFF_SIZE);
   	 	size -= n;
	}

	cout<<"\nsent file\n";
	cout<<"sending RCOM\n";
	int opc = 40;
	send(fd, &opc, sizeof(opc), 0);
	cout<<"sent "<<opc<<endl;
	fclose(fp);
}

void *client_handler(void *ptr)
{
	int fd = *(int *)ptr;
	int opc;
	char filename[BUFF_SIZE];
	char **Karr;
	while(1)
	{
		recv(fd, &opc, sizeof(opc), 0);
		cout<<"\nreceived opcode "<<opc<<" from client\n";
		switch(opc)
		{
			case 10:cout<<"PUBKEY from client\n";
					Karr = Diffie_Hellman(fd);
					break;
			case 20:{
						cout<<"REQSERV from client\n";
						memset(filename, '\0', BUFF_SIZE);
						recv(fd, filename, BUFF_SIZE, 0);
						FILE *fp = fopen(filename, "rb");
						if(fp==NULL)
						{
							cout<<"requested "<<filename<<" file not found on server's directory\n";
							send(fd, &na, sizeof(na), 0);
						}
						else
						{
							cout<<"Uploading file to client\n";
							cout<<"\nsending ENCMSG to client\n";
							send(fd, &thirty, sizeof(thirty), 0);
							fclose(fp);
							send_file(filename, fd, Karr);
							cout<<"\nclient request served\n";
						}
					}
					break;
			case 50:cout<<"DISCONNECT from client\n";
					free(Karr[0]);
					free(Karr[1]);
					free(Karr[2]);
					free(Karr);
					close(fd);
					pthread_exit(NULL);
					break;
			default:cout<<"Unidentifiable message from client\n";
					break;
		}
	}

}

int main(int argc, char const *argv[]) 
{ 
	int server_fd, valread; 
	struct sockaddr_in address; 
	int opt = 1; 
	int addrlen = sizeof(address); 
	char buffer[BUFF_SIZE] = {0}; 	
	
	if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) 
	{ 
		perror("socket failed"); 
		exit(EXIT_FAILURE); 
	} 
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) 
	{ 
		perror("setsockopt"); 
		exit(EXIT_FAILURE); 
	} 
	address.sin_family = AF_INET; 
	address.sin_addr.s_addr = INADDR_ANY; 
	address.sin_port = htons( PORT ); 
	
	if (bind(server_fd, (struct sockaddr *)&address, sizeof(address))<0) 
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
	int count=0;
	while(1)
	{
		int new_socket;
		cout<<"waiting for incoming request\n";
		if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen))<0) 
		{ 
			perror("accept"); 
			exit(EXIT_FAILURE); 
		}
		cout<<"New client connected\n";
		pthread_create(&threads[count++], NULL, client_handler, (void *)&new_socket);
	}
} 
