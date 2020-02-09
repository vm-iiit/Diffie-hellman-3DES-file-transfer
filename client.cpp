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
	Integer p1 = pg1.Prime();
    Integer q1= pg1.SubPrime();
    Integer g1 = pg1.Generator();

	cout << "P1: " << p1 << '\n';
	cout << "Q1: " << q1 << '\n';
	cout << "G1: " << g1 << '\n';
	send_Integer(p1, fd);
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
    char enkey1[sizeof(Key1)];
    memcpy(enkey1, Key1, sizeof(Key1));


    AutoSeededRandomPool rnd2;
	PrimeAndGenerator pg2;
	pg2.Generate(1, rnd2, 64, 63);
	Integer p2 = pg2.Prime();
    Integer q2= pg2.SubPrime();
    Integer g2 = pg2.Generator();

	cout << "P2: " << p2 << '\n';
	cout << "Q2: " << q2 << '\n';
	cout << "G2: " << g2 << '\n';
	send_Integer(p2, fd);
	send_Integer(g2, fd);
	DH dhC2 = DH(p2, q2, g2);
	SecByteBlock privKeyC2, pubKeyC2;
	privKeyC2 = SecByteBlock(dhC2.PrivateKeyLength());
    pubKeyC2 = SecByteBlock(dhC2.PublicKeyLength());
    dhC2.GenerateKeyPair(rnd2, privKeyC2, pubKeyC2);

    Integer pubk2(pubKeyC2, pubKeyC2.size());
    Integer privk2(privKeyC2, privKeyC2.size());
    cout<<"pubkey "<<pubk2<<endl;
    cout<<"privkey "<<privk2<<endl;
    send_Integer(pubk2, fd);

    Integer pubkeyS2 = receive_Integer(fd);
    Integer shared_key2 = ModularExponentiation(pubkeyS2, privk2, p2);
    cout<<"shared key "<<shared_key2<<endl;

    SecByteBlock Key2 = Int2Block(shared_key2);
    char enkey2[sizeof(Key2)];
    memcpy(enkey2, Key2, sizeof(Key2));


    AutoSeededRandomPool rnd3;
	PrimeAndGenerator pg3;
	pg3.Generate(1, rnd1, 64, 63);
	Integer p3 = pg3.Prime();
    Integer q3= pg3.SubPrime();
    Integer g3 = pg3.Generator();

	cout << "P3  " << p3 << '\n';
	cout << "Q3: " << q3 << '\n';
	cout << "G3: " << g3 << '\n';
	send_Integer(p3, fd);
	send_Integer(g3, fd);
	DH dhC3 = CryptoPP::DH(p3, q3, g3);
	SecByteBlock privKeyC3, pubKeyC3;
	privKeyC3 = SecByteBlock(dhC3.PrivateKeyLength());
    pubKeyC3 = SecByteBlock(dhC3.PublicKeyLength());
    dhC3.GenerateKeyPair(rnd3, privKeyC3, pubKeyC3);

    Integer pubk3(pubKeyC3, pubKeyC3.size());
    Integer privk3(privKeyC3, privKeyC3.size());
    cout<<"pubkey "<<pubk3<<endl;
    cout<<"privkey "<<privk3<<endl;
    send_Integer(pubk3, fd);

    Integer pubkeyS3 = receive_Integer(fd);
    Integer shared_key3 = ModularExponentiation(pubkeyS3, privk3, p3);
    cout<<"shared key "<<shared_key3<<endl;

    SecByteBlock Key3 = Int2Block(shared_key3);
    char enkey3[sizeof(Key3)];
    memcpy(enkey3, Key3, sizeof(Key3));

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
		DES_Process(enkey3, block, 1024, CryptoPP::DECRYPTION);
		DES_Process(enkey2, block, 1024, CryptoPP::ENCRYPTION);
		DES_Process(enkey1, block, 1024, CryptoPP::DECRYPTION);
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
