test:
	g++ --std=c++11 -I./src/ src/base64.cpp src/Client.cpp src/ClientManager.cpp src/sha1.cpp src/test.cpp -luv