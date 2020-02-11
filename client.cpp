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

#define PORT 9876
#define BUFF_SIZE 1024
const int ten=10, twenty=20, thirty=30, forty=40, fifty=50;
bool bsync;
char *K1=NULL, *K2=NULL, *K3=NULL;

struct PubKey{
	Integer large_prime;
	Integer primitive_root;
	Integer pubkey;
};

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

void send_Pubkey(struct PubKey spk, int fd)
{
	send_Integer(spk.large_prime, fd);
	send_Integer(spk.primitive_root, fd);
	send_Integer(spk.pubkey, fd);
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

SecByteBlock Int2Block(Integer x)
{
	SecByteBlock bytes;
    size_t encodedSize = x.MinEncodedSize(Integer::UNSIGNED);
    bytes.resize(encodedSize);
    x.Encode(bytes.BytePtr(), encodedSize, Integer::UNSIGNED);
    return bytes;
}


void Diffie_Hellman(int fd)
{
	AutoSeededRandomPool rnd1;
	PrimeAndGenerator pg1;
	pg1.Generate(1, rnd1, 64, 63);
	Integer p1 = pg1.Prime();
    Integer q1= pg1.SubPrime();
    Integer g1 = pg1.Generator();

	cout << "Large prime 1 : " << p1 << '\n';
	cout << "Primitive root 1 : " << g1 << '\n';
	send_Integer(p1, fd);
	send_Integer(g1, fd);
	DH dhC1 = DH(p1, q1, g1);
	SecByteBlock privKeyC1, pubKeyC1;
	privKeyC1 = SecByteBlock(dhC1.PrivateKeyLength());
    pubKeyC1 = SecByteBlock(dhC1.PublicKeyLength());
    dhC1.GenerateKeyPair(rnd1, privKeyC1, pubKeyC1);

    Integer pubk1(pubKeyC1, pubKeyC1.size());
    Integer privk1(privKeyC1, privKeyC1.size());
    cout<<"pubkey 1 :"<<pubk1<<endl;
    cout<<"privkey 1 :"<<privk1<<endl;
    send_Integer(pubk1, fd);

    Integer pubkeyS1 = receive_Integer(fd);
    cout<<"received pubkey1 from server "<<pubkeyS1<<endl;
    Integer shared_key1 = ModularExponentiation(pubkeyS1, privk1, p1);
    cout<<"shared key 1 :"<<shared_key1<<endl<<endl;

    SecByteBlock Key1 = Int2Block(shared_key1);
    char enkey1[sizeof(Key1)];
    memcpy(enkey1, Key1, sizeof(Key1));


    AutoSeededRandomPool rnd2;
	PrimeAndGenerator pg2;
	pg2.Generate(1, rnd2, 64, 63);
	Integer p2 = pg2.Prime();
    Integer q2= pg2.SubPrime();
    Integer g2 = pg2.Generator();

	cout << "Large prime 2 : " << p2 << '\n';
	cout << "Primitive root 2 : " << g2 << '\n';
	send_Integer(p2, fd);
	send_Integer(g2, fd);
	DH dhC2 = DH(p2, q2, g2);
	SecByteBlock privKeyC2, pubKeyC2;
	privKeyC2 = SecByteBlock(dhC2.PrivateKeyLength());
    pubKeyC2 = SecByteBlock(dhC2.PublicKeyLength());
    dhC2.GenerateKeyPair(rnd2, privKeyC2, pubKeyC2);

    Integer pubk2(pubKeyC2, pubKeyC2.size());
    Integer privk2(privKeyC2, privKeyC2.size());
    cout<<"pubkey 2 :"<<pubk2<<endl;
    cout<<"privkey 2 :"<<privk2<<endl;
    send_Integer(pubk2, fd);

    Integer pubkeyS2 = receive_Integer(fd);
    cout<<"received pubkey2 from server "<<pubkeyS2<<endl;
    Integer shared_key2 = ModularExponentiation(pubkeyS2, privk2, p2);
    cout<<"shared key 2 :"<<shared_key2<<endl<<endl;

    SecByteBlock Key2 = Int2Block(shared_key2);
    char enkey2[sizeof(Key2)];
    memcpy(enkey2, Key2, sizeof(Key2));


    AutoSeededRandomPool rnd3;
	PrimeAndGenerator pg3;
	pg3.Generate(1, rnd1, 64, 63);
	Integer p3 = pg3.Prime();
    Integer q3= pg3.SubPrime();
    Integer g3 = pg3.Generator();

	cout << "Large prime 3 :" << p3 << '\n';
	cout << "Primitive root 3 :" << g3 << '\n';
	send_Integer(p3, fd);
	send_Integer(g3, fd);
	DH dhC3 = CryptoPP::DH(p3, q3, g3);
	SecByteBlock privKeyC3, pubKeyC3;
	privKeyC3 = SecByteBlock(dhC3.PrivateKeyLength());
    pubKeyC3 = SecByteBlock(dhC3.PublicKeyLength());
    dhC3.GenerateKeyPair(rnd3, privKeyC3, pubKeyC3);

    Integer pubk3(pubKeyC3, pubKeyC3.size());
    Integer privk3(privKeyC3, privKeyC3.size());
    cout<<"pubkey 3 :"<<pubk3<<endl;
    cout<<"privkey 3 :"<<privk3<<endl;
    send_Integer(pubk3, fd);

    Integer pubkeyS3 = receive_Integer(fd);
    cout<<"received pubkey3 from server "<<pubkeyS3<<endl;
    Integer shared_key3 = ModularExponentiation(pubkeyS3, privk3, p3);
    cout<<"shared key 3 :"<<shared_key3<<endl<<endl;

    SecByteBlock Key3 = Int2Block(shared_key3);
    char enkey3[sizeof(Key3)];
    memcpy(enkey3, Key3, sizeof(Key3));

    K1 = (char*)malloc(sizeof(enkey1));
    K2 = (char*)malloc(sizeof(enkey2));
    K3 = (char*)malloc(sizeof(enkey3));

    memcpy(K1, enkey1, sizeof(enkey1));
    memcpy(K2, enkey2, sizeof(enkey2));
    memcpy(K3, enkey3, sizeof(enkey3));
    cout<<"\n3 Keys obtained\n";
}

void file_download(string filename, int fd)
{
	int opc=0;
	send(fd, filename.c_str(), BUFF_SIZE, 0);
    byte block[BUFF_SIZE];
    char buffer[BUFF_SIZE];

    while(1)
    {
    	cout<<"waiting for ENCMSG from server\n";
    	recv(fd, &opc, sizeof(opc), 0);
    	if(opc == 30)
    		break;
    	else
    	{
    		cout<<"requested file not available with server, try some other filename or enter E to exit\n";
    		cin.clear();
    		fflush(stdin);
    		getline(cin, filename);
    		remove(filename.c_str());
    		if(filename == "E")
    		{
    			send(fd, &fifty, sizeof(fifty), 0);
    			cout<<"Exiting\n";
    			exit(0);
    		}
    		send(fd, &twenty, sizeof(twenty), 0);
    		send(fd, filename.c_str(), BUFF_SIZE, 0);
    	}
    }

    cout<<"received ENCMSG from server\n";
    long long int fsize;
    ssize_t n;
	FILE *fp = fopen(filename.c_str(), "wb");
	recv(fd, &fsize, sizeof(fsize), 0);
	cout<<"got file size as "<<fsize<<" bytes"<<endl;
	memset(block, '\0', sizeof(block));
	cout<<"Downlading the requested file from server\n";
	int lc=0;
	while(fsize > 0)
	{	
		send(fd, &bsync, sizeof(bsync), 0);
		recv(fd, &n, sizeof(n), 0);
		recv(fd, block, n*sizeof(byte), 0);	
		DES_Process(K3, block, BUFF_SIZE, CryptoPP::DECRYPTION);
		DES_Process(K2, block, BUFF_SIZE, CryptoPP::ENCRYPTION);
		DES_Process(K1, block, BUFF_SIZE, CryptoPP::DECRYPTION);
		memset(buffer, '\0', BUFF_SIZE);
		memcpy(buffer, block, BUFF_SIZE);
		fwrite (buffer, sizeof(char), n, fp);
		memset ( block , '\0', BUFF_SIZE);
		fsize -= n;
	}
	cout<<"file transfer complete\n";
	recv(fd, &opc, sizeof(opc), 0);
	cout<<"\ngot REQCOM from server\n";
	cout<<"file downloaded\n";
	fclose(fp);
}

int main(int argc, char const *argv[]) 
{ 
	int sock = 0, valread; 
	struct sockaddr_in serv_addr; 
	char buffer[BUFF_SIZE] = {0}; 
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
	{ 
		printf("\n Socket creation error \n"); 
		return -1; 
	} 

	serv_addr.sin_family = AF_INET; 
	serv_addr.sin_port = htons(PORT); 
	
	if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0) 
	{ 
		printf("\nInvalid address/ Address not supported \n"); 
		return -1; 
	} 
	
	if ((connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr))) < 0) 
	{ 
		printf("\nConnection Failed \n"); 
		return -1; 
	}

	string filename;
	char ch;
	cout<<"PUBKEY\nSending Public keys to server \n";
	send(sock, &ten, sizeof(ten), 0);
	Diffie_Hellman(sock);
	while(1)
	{
		cin.clear();
		fflush(stdin);
		cout<<"\nEnter name of file to be downloaded :";
		getline(cin, filename);
		if(remove(filename.c_str()) == 0)
			cout<<"overwriting existing file\n";
		cout<<"sending REQSERV to server\n";
		send(sock, &twenty, sizeof(twenty), 0);
		file_download(filename, sock);
		cout<<"sending DISCONNECT to server\n";
		send(sock, &fifty, sizeof(fifty), 0);
		close(sock);
		break;
	}
	return 0; 
} 
