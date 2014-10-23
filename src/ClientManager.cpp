/*

The MIT License (MIT)

Copyright (c) 2014 Matheus Valadares

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

#include "ClientManager.h"
#include "Client.h"
#include <thread>

namespace {
	uv_loop_t g_Loop;
	uv_tcp_t g_Server;
};

std::thread::id g_WSUV_MainThreadID;
std::vector<Client*> g_WSUV_Clients;

void ClientManager::Init(){
	//printf("Running libuv version %s\n", uv_version_string());
	g_WSUV_MainThreadID = std::this_thread::get_id();
	
#ifndef _WIN32
	signal(SIGPIPE, SIG_IGN);
#endif

	uv_loop_init(&g_Loop);
	
	uv_tcp_init(&g_Loop, &g_Server);
	struct sockaddr_in addr;
#ifdef DEBUG
	uv_ip4_addr("0.0.0.0", 8080, &addr);
#else
	uv_ip4_addr("0.0.0.0", 80, &addr);
#endif
	uv_tcp_nodelay(&g_Server, true);
	if(uv_tcp_bind(&g_Server, (const struct sockaddr*) &addr, 0) != 0){
		puts("wsuv: Couldn't bind tcp socket");
		exit(1);
	}
	
	if(uv_listen((uv_stream_t*) &g_Server, 256, OnConnection) != 0){
		puts("wsuv: Couldn't start listening");
		exit(1);
	}

}


void ClientManager::OnConnection(uv_stream_t* server, int status){
	if(status < 0) return;

	auto clientObj = new WSUV_ClientClass();
	uv_tcp_t *client = &clientObj->m_Socket;
	client->data = clientObj;

	uv_tcp_init(&g_Loop, client);
	if(uv_accept(server, (uv_stream_t*) client) == 0){
		// We have to turn off the delay, because it seems that when you open a server
		// on port 80, it's enabled automatically, WTF?
		uv_tcp_nodelay(client, true);
		uv_read_start((uv_stream_t*) client, AllocBuffer, OnSocketData);
	}else{
		uv_close((uv_handle_t*) client, [](uv_handle_t* handle){
			delete (Client*) handle->data;
		});
	}
}

void ClientManager::AllocBuffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf){
	buf->base = new char[suggested_size];
	buf->len = suggested_size;
}

void ClientManager::OnSocketData(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf){
	Client *client = (Client*) stream->data;
	if(nread < 0){
		client->Destroy();
		return;
	}else{
		if(nread != 0){
			client->OnSocketData(buf->base, (size_t) nread);
		}
	}

	if(buf != nullptr) delete[] buf->base;
}

void ClientManager::Run(){
	for(size_t i = 0; i < g_WSUV_Clients.size(); ++i){
		Client *client = g_WSUV_Clients[i];
		if(client == nullptr) continue;
		client->CheckQueuedPackets();
	}
	
	uv_run(&g_Loop, UV_RUN_NOWAIT);
}

void ClientManager::Destroy(){
	uv_close((uv_handle_t*) &g_Server, nullptr);
	uv_loop_close(&g_Loop);
}
