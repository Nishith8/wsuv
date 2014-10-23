#ifndef WSUV_CLIENTMANAGER_H
#define WSUV_CLIENTMANAGER_H

// Extend the class Client, and change this to the new name
#define WSUV_ClientClass Client
// Also add its include in here:
#include "Client.h"

class ClientManager {
public:
	static void Init();
	static void Run();
	static void Destroy();
	
private:
	static void OnConnection(uv_stream_t* server, int status);
	static void AllocBuffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);
	static void OnSocketData(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
};

#endif
