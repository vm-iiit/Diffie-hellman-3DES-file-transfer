#include <stdio.h>
#include<iostream>
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <unistd.h> 
#include <string.h> 
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
const bool tval = true, fval = false;

#define PORT 8080
#define BUFF_SIZE 64

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

SecByteBlock Int2Block(Integer x)
{
	SecByteBlock bytes;
    size_t encodedSize = x.MinEncodedSize(Integer::UNSIGNED);
    bytes.resize(encodedSize);
    x.Encode(bytes.BytePtr(), encodedSize, Integer::UNSIGNED);
    return bytes;
}


void DH_auth(int fd)
{
	AutoSeededRandomPool rnd1;
	PrimeAndGenerator pg1;
	pg1.Generate(1, rnd1, 64, 63);
	CryptoPP::Integer p1 = pg1.Prime();
    CryptoPP::Integer q1= pg1.SubPrime();
    CryptoPP::Integer g1 = pg1.Generator();

	std::cout << "P1: " << p1 << '\n';
	std::cout << "Q1: " << q1 << '\n';
	std::cout << "G1: " << g1 << '\n';

	//sending p
	send_Integer(p1, fd);

	//sending g
	send_Integer(g1, fd);

	DH dhC1 = CryptoPP::DH(p1, q1, g1);
	

	SecByteBlock privKeyC1, pubKeyC1;
	privKeyC1 = SecByteBlock(dhC1.PrivateKeyLength());
    pubKeyC1 = SecByteBlock(dhC1.PublicKeyLength());
    dhC1.GenerateKeyPair(rnd1, privKeyC1, pubKeyC1);

    Integer pubk1(pubKeyC1, pubKeyC1.size());
    Integer privk1(privKeyC1, privKeyC1.size());
    cout<<"pubkey "<<pubk1<<endl;
    cout<<"privkey "<<privk1<<endl;
    send_Integer(pubk1, fd);

    Integer pubkeyS1 = receive_Integer(fd);
    Integer shared_key1 = ModularExponentiation(pubkeyS1, privk1, p1);
    cout<<"shared key "<<shared_key1<<endl;

    SecByteBlock Key1 = Int2Block(shared_key1);
    char enkey[sizeof(Key1)];
    memcpy(enkey, Key1, sizeof(Key1));

    byte block[1024];
    char buffer[1024];
	
    int fsize;
	string comppath = "video.mkv";
	
	FILE *fp = fopen (comppath.c_str(), "wb");
	ssize_t n;
	recv(fd, &fsize, sizeof(fsize), 0);
	cout<<"got file size "<<fsize<<endl;
	memset(block, '\0', sizeof(block));
	while(( n = recv(fd, block, 1024, 0)) > 0)
	{	
		// cout<<"encrypted text :"<<block<<endl;
		DES_Process(enkey, block, 1024, CryptoPP::DECRYPTION);
		// cout<<"decrypted text :\n";
		// cout<<block<<endl;
		memset(buffer, '\0', 1024);
		memcpy(buffer, block, 1024);
		fwrite (buffer, sizeof(char), 1024, fp);
		memset ( block , '\0', BUFF_SIZE);
	} 
	cout<<"file downloaded\n";
    close(fd);
	fclose(fp);
}

int main(int argc, char const *argv[]) 
{ 
	int sock = 0, valread; 
	struct sockaddr_in serv_addr; 
	char *hello = "Hello from client"; 
	char buffer[1024] = {0}; 
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
	{ 
		printf("\n Socket creation error \n"); 
		return -1; 
	} 

	serv_addr.sin_family = AF_INET; 
	serv_addr.sin_port = htons(PORT); 
	
	// Convert IPv4 and IPv6 addresses from text to binary form 
	if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0) 
	{ 
		printf("\nInvalid address/ Address not supported \n"); 
		return -1; 
	} 
	// int nfd;
	if ((connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr))) < 0) 
	{ 
		printf("\nConnection Failed \n"); 
		return -1; 
	}
	
	DH_auth(sock);
	return 0; 
} 
