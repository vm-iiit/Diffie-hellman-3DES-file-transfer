all:
	g++ client.cpp -lpthread -lcryptopp -o client.out
	g++ server.cpp -lcryptopp -lpthread -o server.out