#ifndef WSUV_ECHOCLIENT_H
#define WSUV_ECHOCLIENT_H

#include "Client.h"
#include <cstdio>
#include <cstring>

class EchoClient : public Client {
	void OnInit(){};
	void OnDestroy(){};
	void OnData(const char *data, size_t length){
		auto packet = CreatePacket(length);
		memcpy(packet, data, length);
		SendPacket(packet);
		DestroyPacket(packet);
	}
};

#endif