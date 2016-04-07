#include "stdafx.h"
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
	uv_tcp_t g_Server;
};

std::thread::id g_WSUV_MainThreadID;
std::vector<Client*> g_WSUV_Clients;
extern uv_loop_t g_Loop;

#ifndef _WIN32
SSL_CTX *g_WSUUV_SSLContext;
#endif

void ClientManager::Init(int port) {
	//printf("Running libuv version %s\n", uv_version_string());
	g_WSUV_MainThreadID = std::this_thread::get_id();

#ifndef _WIN32
	signal(SIGPIPE, SIG_IGN);
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	ERR_load_crypto_strings();
	g_WSUUV_SSLContext = SSL_CTX_new(SSLv23_server_method());
	
	int r = 0;
	r = SSL_CTX_set_cipher_list(g_WSUUV_SSLContext, "ALL:!EXPORT:!LOW");
	if(r != 1) {
		ERR_print_errors_fp(stdout);
		g_WSUUV_SSLContext = nullptr;
	}else{
		SSL_CTX_set_verify(g_WSUUV_SSLContext, SSL_VERIFY_NONE, [](int ok, X509_STORE_CTX* ctx){ return 1; });

		r = SSL_CTX_use_certificate_file(g_WSUUV_SSLContext, "server.crt", SSL_FILETYPE_PEM);
		if(r != 1) {
			ERR_print_errors_fp(stdout);
			g_WSUUV_SSLContext = nullptr;
		}else{
			r = SSL_CTX_use_PrivateKey_file(g_WSUUV_SSLContext, "server.key", SSL_FILETYPE_PEM);
			if(r != 1) {
				ERR_print_errors_fp(stdout);
				g_WSUUV_SSLContext = nullptr;
			}else{
				r = SSL_CTX_check_private_key(g_WSUUV_SSLContext);
				if(r != 1) {
					ERR_print_errors_fp(stdout);
					g_WSUUV_SSLContext = nullptr;
				}
			}
		}
	}
	
	if(r == 1){
		puts("SSL setup successfully");
	}else{
		puts("SSL setup failing, rejecting SSL clients");
	}
	
#endif  
	
	uv_tcp_init(&g_Loop, &g_Server);
	struct sockaddr_in addr;
	uv_ip4_addr("0.0.0.0", port, &addr);
	uv_tcp_nodelay(&g_Server, (int) true);
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
		uv_tcp_nodelay(client, (int) true);
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
	}else{
		if(nread != 0){
			client->OnSocketData((unsigned char*)buf->base, (size_t) nread); //-V595
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
}

void ClientManager::Destroy(){
	uv_close((uv_handle_t*) &g_Server, nullptr);
	EVP_cleanup();
	ERR_free_strings();
}
