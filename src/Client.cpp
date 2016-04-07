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

#include "Client.h"
#include "sha1.h"
#include "base64.h"
#include "ClientManager.h"

#define HEADER_PADDING 10

struct DataFrameHeader {
	char data[2];

	DataFrameHeader() { data[0] = 0; data[1] = 0; }

	void fin(bool v) { data[0] &= ~(1 << 7); data[0] |= v << 7; }
	void rsv1(bool v) { data[0] &= ~(1 << 6); data[0] |= v << 6; }
	void rsv2(bool v) { data[0] &= ~(1 << 5); data[0] |= v << 5; }
	void rsv3(bool v) { data[0] &= ~(1 << 4); data[0] |= v << 4; }
	void mask(bool v) { data[1] &= ~(1 << 7); data[1] |= v << 7; }
	void opcode(uint8_t v) {
		data[0] &= ~0x0F;
		data[0] |= v & 0x0F;
	}

	void len(uint8_t v) {
		data[1] &= ~0x7F;
		data[1] |= v & 0x7F;
	}

	bool fin() { return (data[0] >> 7) & 1; }
	bool rsv1() { return (data[0] >> 6) & 1; }
	bool rsv2() { return (data[0] >> 5) & 1; }
	bool rsv3() { return (data[0] >> 4) & 1; }
	bool mask() { return (data[1] >> 7) & 1; }

	uint8_t opcode() {
		return data[0] & 0x0F;
	}

	uint8_t len() {
		return data[1] & 0x7F;
	}
};


struct WriteRequestPart;
struct WriteRequest {
	uv_write_t req;
	WriteRequestPart *part;
	Client *client;
};

struct WriteRequestPart {
	uv_buf_t buf;
	size_t packetLen;
	size_t headerLen;
	int refCount;
};


extern std::vector<Client*> g_WSUV_Clients;
extern SSL_CTX *g_WSUUV_SSLContext;

namespace {
	
	WriteRequestPart* PacketToWriteRequest(unsigned char *packet) {
		return (WriteRequestPart*)(packet - sizeof(WriteRequestPart) - HEADER_PADDING);
	}

}


static_assert(sizeof(DataFrameHeader) == 2, "DataFrame basic header must have 2 bytes");

Client::Client(){
	for(size_t i = 0; i < g_WSUV_Clients.size(); ++i){
		if(g_WSUV_Clients[i] != nullptr) continue;
		g_WSUV_Clients[i] = this;
		goto AddedMe;
	}
	
	g_WSUV_Clients.push_back(this);
	
	AddedMe:;
}

Client::~Client(){
	for(size_t i = 0; i < g_WSUV_Clients.size(); ++i){
		if(g_WSUV_Clients[i] != this) continue;
		g_WSUV_Clients[i] = nullptr;
		break;
	}
	
	m_bClosing = true;
	m_bDestroyed = true;
	
	for(auto &d : m_Frames){
		delete[] d.data;
	}

	for(unsigned char *packet : m_QueuedPackets){
		WriteRequestPart *part = PacketToWriteRequest(packet);
		if(--part->refCount == 0) delete[] (char*)part;
	}
}

void Client::Destroy(const char *reason){
	m_bClosing = true;

	if(m_bDestroyed) return;
	m_bDestroyed = true;
	
	if(reason != nullptr){
#ifdef DEBUG
		printf("Client disconnected: %s\n", reason);
#endif
	}
	
#ifndef _WIN32
	if(m_bSecure){
		SSL_free(m_SSL);
		m_SSL = nullptr;
		m_SSL_write = nullptr;
		m_SSL_read = nullptr;
	}
#endif
	
	OnDestroy();
	
	
	auto req = new uv_shutdown_t;
	req->data = this;
	
	uv_shutdown(req, (uv_stream_t*)&m_Socket, [](uv_shutdown_t* req, int status) {
		Client *self = (Client*)req->data;
		delete req;
		
		uv_close((uv_handle_t*) &self->m_Socket, [](uv_handle_t* handle){
			Client *client = (Client*) handle->data;
			delete client;
		});
	});
}

#ifndef _WIN32
void Client::HandleSSLError(int err){
	if(err == SSL_ERROR_WANT_WRITE){
		FlushSSLWrite();
	}else if(err == SSL_ERROR_WANT_READ){
		// It's async
	}else{
		Destroy("ssl_error_1");
	}
}

void Client::FlushSSLWrite(){
FlushAgain:
	if(m_bClosing || m_bDestroyed) return;
	char *buf = new char[4096];
	auto res = BIO_read(m_SSL_write, buf, 4096);
	if(res > 0){
		WriteRaw(buf, res, true);
		goto FlushAgain;
	}else{
		delete[] buf;
		
		bool shouldRetry = BIO_should_retry(m_SSL_write);
		
		if(!shouldRetry){
			// Connection closed normally
			if(res == 0){
				Destroy("ssl_close");
			}else{
				HandleSSLError(SSL_get_error(m_SSL, res));
			}
		}
	}
}

#endif

void Client::OnSocketData(unsigned char *data, size_t len){
	if(m_bClosing || m_bDestroyed || len == 0) return;
	
	// Sniff if we're using SSL
	if(m_bWaitingForFirstPacket){
		m_bWaitingForFirstPacket = false;
#ifndef _WIN32
		if(data[0] == 0x16 || data[0] == 0x80){
			if(g_WSUUV_SSLContext == nullptr){
#ifdef DEBUG
				printf("No SSL context, rejecting client\n");
#endif
				Destroy("no_ssl_support");
				return;
			}
			
			m_bSecure = true;
			m_bDoingSSLHandshake = true;
			m_SSL = SSL_new(g_WSUUV_SSLContext);
			m_SSL_read = BIO_new(BIO_s_mem());
			m_SSL_write = BIO_new(BIO_s_mem());
			
			SSL_set_bio(m_SSL, m_SSL_read, m_SSL_write);
			SSL_set_accept_state(m_SSL);
		}
#endif
	}
	
	
#ifndef _WIN32
	if(m_bSecure){
		BIO_write(m_SSL_read, data, len);
		
		/*
		if(m_bDoingSSLHandshake){
			auto res = SSL_do_handshake(m_SSL);
			if(res > 0){
				m_bDoingSSLHandshake = false;
			} else {
				HandleSSLError(SSL_get_error(m_SSL));
				return;
			}
		}
		
		assert(SSL_is_init_finished(m_SSL));
		*/
		
		unsigned char buf[2048];
		for(;;){
			if(m_bClosing || m_bDestroyed) break;
			auto res = SSL_read(m_SSL, buf, sizeof(buf));
			if(res > 0){
				OnSocketData2(buf, res);
			}else{
				HandleSSLError(SSL_get_error(m_SSL, res));
				break;
			}
		}
		
		FlushSSLWrite();
		return;
	}
#endif
	
	OnSocketData2(data, len);
}

void Client::OnSocketData2(unsigned char *data, size_t len){
	if(m_bClosing || m_bDestroyed) return;
	
	// This should still give us a byte to put a null terminator
	// during the http phase
	if(m_iBufferPos + len >= sizeof(m_Buffer)){
		Destroy("buffer_overflowed");
		return;
	}

	memcpy(&m_Buffer[m_iBufferPos], data, len);
	m_iBufferPos += len;
	m_Buffer[m_iBufferPos] = 0;

	if(!m_bHasCompletedHandshake){
		// Haven't completed the header yet
		if(strstr((char*)m_Buffer, "\r\n\r\n") == nullptr) return;

		const char *str = (char*)m_Buffer;

		bool badHeader = false;

		// First line is a weird one, ignore it
		str = strstr(str, "\r\n") + 2; //-V519

		bool hasUpgradeHeader = false;
		bool hasConnectionHeader = false;
		bool sendMyVersion = false;
		bool hasVersionHeader = false;
		bool hasSecurityKey = false;
		std::string securityKey;

		for(;;) {
			auto nextLine = strstr(str, "\r\n");
			// This means that we have finished parsing the headers
			if(nextLine == str) {
				break;
			}

			if(nextLine == nullptr) {
				badHeader = true;
				break;
			}

			auto colonPos = strstr(str, ":");
			if(colonPos == nullptr || colonPos > nextLine) {
				badHeader = true;
				break;
			}

			auto keyPos = str;
			ssize_t keyLength = colonPos - keyPos;
			auto valuePos = colonPos + 1;
			while(*valuePos == ' ') ++valuePos;
			ssize_t valueLength = nextLine - valuePos;

			if(strncmp("Upgrade", keyPos, keyLength) == 0) {
				hasUpgradeHeader = true;
				if(strncmp("websocket", valuePos, valueLength) != 0 && strncmp("Websocket", valuePos, valueLength) != 0) {
					badHeader = true;
					break;
				}
			} else if(strncmp("Connection", keyPos, keyLength) == 0) {
				hasConnectionHeader = true;
				auto uppos = strstr(valuePos, "Upgrade");
				if(uppos == nullptr || uppos > nextLine) {
					badHeader = true;
					break;
				}
			} else if(strncmp("Sec-WebSocket-Key", keyPos, keyLength) == 0) {
				hasSecurityKey = true;
				securityKey = std::string(valuePos, valueLength);
			} else if(strncmp("Sec-WebSocket-Version", keyPos, keyLength) == 0) {
				hasVersionHeader = true;
				if(strncmp("13", valuePos, valueLength) != 0) {
					sendMyVersion = true;
				}
			} else if(strncmp("Sec-WebSocket-Extensions", keyPos, keyLength) == 0){
				auto p = strstr(valuePos, "permessage-deflate");
				if(p != nullptr && p <= nextLine) {
#ifdef DEBUG
					//m_bCompressionEnabled = true;
#endif
				}
			} else if(strncmp("Origin", keyPos, keyLength) == 0) {
				if(strncmp("http://localhost", valuePos, valueLength) != 0
					&& strncmp("http://agar.io", valuePos, valueLength) != 0
					&& strncmp("http://10.10.2.13", valuePos, valueLength) != 0
					&& strncmp("https://localhost", valuePos, valueLength) != 0
					&& strncmp("https://agar.io", valuePos, valueLength) != 0
					&& strncmp("https://10.10.2.13", valuePos, valueLength) != 0
				) {
					badHeader = true;
					break;
				}
			}

			str = nextLine + 2;
		}

		if(!hasUpgradeHeader) badHeader = true;
		if(!hasConnectionHeader) badHeader = true;
		if(!hasVersionHeader) badHeader = true;
		if(!hasSecurityKey) badHeader = true;


#define EXPAND_LITERAL(x) x, strlen(x)

		if(badHeader) {
			WriteAndDestroy(EXPAND_LITERAL("HTTP/1.1 400 Bad Request\r\n\r\n"));
			return;
		}

		securityKey += "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
		unsigned char hash[20];
		sha1::calc(securityKey.data(), securityKey.size(), hash);
		auto solvedHash = base64_encode(hash, sizeof(hash));
		auto allocatedHash = new char[solvedHash.size()];
		memcpy(allocatedHash, solvedHash.data(), solvedHash.size());

		Write(EXPAND_LITERAL("HTTP/1.1 101 Switching Protocols\r\n"));
		Write(EXPAND_LITERAL("Upgrade: websocket\r\n"));
		Write(EXPAND_LITERAL("Connection: Upgrade\r\n"));
		if(sendMyVersion) {
			Write(EXPAND_LITERAL("Sec-WebSocket-Version: 13\r\n"));
		}

		Write(EXPAND_LITERAL("Sec-WebSocket-Accept: "));
		Write(allocatedHash, solvedHash.size(), true);
		Write(EXPAND_LITERAL("\r\n\r\n"));

		m_bHasCompletedHandshake = true;

		// Reset buffer, notice that this assumes that the browser won't send anything before
		// waiting for the header response to come.
		m_iBufferPos = 0;

		OnInit();

#undef EXPAND_LITERAL

		return;
	}
	
	// Websockets
	
	for(;;){
		// Not enough to read the header
		if(m_iBufferPos < 2) return;
		
		auto &header = *(DataFrameHeader*) m_Buffer;
		
		if(header.rsv1()) {
			Destroy("used_rsv1");
			return;
		}
		
		if(header.rsv2() || header.rsv3()){
			Destroy("used_rsv23");
			return;
		}

		unsigned char *curPosition = m_Buffer + 2;

		size_t frameLength = header.len();
		if(frameLength == 126){
			if(m_iBufferPos < 4) return;
			frameLength = (*(uint8_t*)(curPosition) << 8) | (*(uint8_t*)(curPosition + 1));
			curPosition += 2;
		}else if(frameLength == 127){
			if(m_iBufferPos < 10) return;

			frameLength = ((uint64_t)*(uint8_t*)(curPosition) << 56) | ((uint64_t)*(uint8_t*)(curPosition + 1) << 48)
				| ((uint64_t)*(uint8_t*)(curPosition + 2) << 40) | ((uint64_t)*(uint8_t*)(curPosition + 3) << 32)
				| (*(uint8_t*)(curPosition + 4) << 24) | (*(uint8_t*)(curPosition + 5) << 16)
				| (*(uint8_t*)(curPosition + 6) << 8) | (*(uint8_t*)(curPosition + 7) << 0);

			curPosition += 8;
		}

		auto amountLeft = m_iBufferPos - (curPosition - m_Buffer);
		const unsigned char *maskKey = nullptr;
		if(header.mask()){
			if(amountLeft < 4) return;
			maskKey = curPosition;
			curPosition += 4;
			amountLeft -= 4;
		}

		if(frameLength > amountLeft) return;

		// Fast path, we received a whole frame and we don't need to combine it with anything
		// Op codes can also never be fragmented, so we put them in here too
		if(header.opcode() >= 0x08 || (m_Frames.empty() && header.fin())){
			if(header.mask()){
				for(size_t i = 0; i < frameLength; ++i){
					curPosition[i] ^= maskKey[i % 4];
				} 
			}

			ProcessDataFrame(header.opcode(), curPosition, frameLength);
		}else{
			{
				DataFrame frame = { header.opcode(), new char[frameLength], frameLength };
				memcpy(frame.data, curPosition, frameLength);
				if(header.mask()){
					for(size_t i = 0; i < frameLength; ++i){
						frame.data[i] ^= maskKey[i % 4];
					} 
				}
				m_Frames.push_back(frame);
			}
				

			if(header.fin()){
				// Assemble frame
				size_t totalLength = 0;
				for(DataFrame &frame : m_Frames){
					totalLength += frame.len;
				}

				unsigned char *allFrames = new unsigned char[totalLength];
				size_t allFramesPos = 0;
				for(DataFrame &frame : m_Frames){
					memcpy(allFrames + allFramesPos, frame.data, frame.len);
					allFramesPos += frame.len;
					delete[] frame.data;
				}

				ProcessDataFrame(m_Frames[0].opcode, allFrames, totalLength);
				
				m_Frames.clear();
				delete[] allFrames;
			} else {
				size_t totalLen = 0;
				for(DataFrame &frame : m_Frames) {
					totalLen += frame.len;
				}

				if(totalLen >= 16 * 1024) Destroy("too_many_frames");
			}
			
		}

		size_t consumed = (curPosition - m_Buffer) + frameLength;
		memmove(m_Buffer, &m_Buffer[consumed], m_iBufferPos - consumed);
		m_iBufferPos -= consumed;
	}
}
void Client::ProcessDataFrame(uint8_t opcode, const unsigned char *rdata, size_t rlen){
	const unsigned char *data = nullptr;

	size_t len;
	data = rdata;
	len = rlen;

	if(opcode == 9){
		// Ping
		unsigned char *packet = CreatePacket(len, 10);
		memcpy(packet, data, len);
		SendPacket(packet);
		DestroyPacket(packet);
		return;
	}

	if(opcode == 8){
		// Close
		Destroy(nullptr);
		return;
	}

	if(opcode == 1 || opcode == 2){
		OnData(data, len);
		return;
	}
}

unsigned char *Client::CreatePacket(size_t len, uint8_t opcode){
	// Creates the packet in this format:
	// [WriteRequestPart] ...[Padding if needed] [DataFrameHeader] [data]
	// The padding is added to make DataFrameHeader always use 10 bytes.
	// We need to do that, since we just return a pointer to data, and we need
	// to be able to get back to WriteRequestPart. It's easier if we just make the
	// header always use 10 bytes.

	size_t headerLen = 2;
	if(len >= 126){
		if(len > UINT16_MAX){
			headerLen += 8;
		}else{
			headerLen += 2;
		}
	}

	unsigned char *data = new unsigned char[sizeof(WriteRequestPart)+HEADER_PADDING + len];

	WriteRequestPart *req = (WriteRequestPart*) data;
	auto headerStart = (data + sizeof(WriteRequestPart)+HEADER_PADDING - headerLen);

	req->buf.len = headerLen + len;
	req->buf.base = (char*)headerStart;


	req->refCount = 1;
	req->headerLen = headerLen;
	req->packetLen = len;

	auto &header = *(DataFrameHeader*)headerStart;
	header.fin(true);
	header.opcode(opcode);
	header.mask(false);
	header.rsv1(false);
	header.rsv2(false);
	header.rsv3(false);;
	if(len >= 126){
		if(len > UINT16_MAX){
			header.len(127);
			*(uint8_t*)(headerStart + 2) = (len >> 56) & 0xFF;
			*(uint8_t*)(headerStart + 3) = (len >> 48) & 0xFF;
			*(uint8_t*)(headerStart + 4) = (len >> 40) & 0xFF;
			*(uint8_t*)(headerStart + 5) = (len >> 32) & 0xFF;
			*(uint8_t*)(headerStart + 6) = (len >> 24) & 0xFF;
			*(uint8_t*)(headerStart + 7) = (len >> 16) & 0xFF;
			*(uint8_t*)(headerStart + 8) = (len >> 8) & 0xFF;
			*(uint8_t*)(headerStart + 9) = (len >> 0) & 0xFF;
		}else{
			header.len(126);
			*(uint8_t*)(headerStart + 2) = (len >> 8) & 0xFF;
			*(uint8_t*)(headerStart + 3) = (len >> 0) & 0xFF;
		}
	}else{
		header.len(len);	
	}

	return data + sizeof(WriteRequestPart)+HEADER_PADDING;
}

void Client::CheckQueuedPackets(){
	if(m_bClosing || m_bDestroyed || m_bWaitingForFirstPacket) return;
	
	std::vector<unsigned char*> cpy;
	std::swap(cpy, m_QueuedPackets);
	for(unsigned char *packet : cpy){
		WriteRequestPart *part = PacketToWriteRequest(packet);
		SendPacket(packet);
		if(--part->refCount == 0) delete[] (char*)part;
	}
}

void Client::SendPacket(unsigned char *packet){
	assert(packet != nullptr);
	if(m_bClosing || m_bDestroyed) return;
	
	WriteRequestPart *part = PacketToWriteRequest(packet);
	assert(part != nullptr);
	
	++part->refCount;
	
	if(m_bWaitingForFirstPacket){
		m_QueuedPackets.push_back(packet);
		return;
	}
	

	if(!uv_is_writable((uv_stream_t*) &m_Socket)){
		if(--part->refCount == 0) delete[] (char*)part;
		Destroy("unwritable_3");
		return;
	}
	
#ifndef _WIN32
	if(m_bSecure){
		SSL_write(m_SSL, part->buf.base, part->buf.len);
		FlushSSLWrite();
		if(--part->refCount == 0) delete[] (char*)part;
		return;
	}
#endif
	
	WriteRequest *req = new WriteRequest;
	req->part = part;
	req->client = this;
	
	uv_write(&req->req, (uv_stream_t*) &m_Socket, &part->buf, 1, [](uv_write_t* req2, int status){
		WriteRequest *req = (WriteRequest *) req2;
		if(status < 0){
			req->client->Destroy("write_failed_2");
		}

		if(--req->part->refCount == 0){
			delete[] (char*)req->part;
		}
		delete req;
	});
}

void Client::WriteAndDestroy(const char *data, size_t len){
	if(m_bClosing || m_bDestroyed || m_bWaitingForFirstPacket) return;
	
#ifndef _WIN32
	if(m_bSecure){
		//FIXME
		Destroy("write_and_destroy_ssl");
		return;
	}
#endif
	
	if(!uv_is_writable((uv_stream_t*) &m_Socket)){
		Destroy("unwritable_2");
		return;
	}

	m_bClosing = true;

	struct CustomWriteRequest {
		uv_write_t req;
		uv_buf_t buf;
		Client *client;
	};

	auto request = new CustomWriteRequest();
	request->buf.base = (char*) data;
	request->buf.len = len;
	request->client = this;

	uv_write(&request->req, (uv_stream_t*) &m_Socket, &request->buf, 1, [](uv_write_t* req, int status){
		auto request = (CustomWriteRequest*) req;
		request->client->Destroy("write_and_destroy");
		delete request;
	});
}

void Client::Write(const char *data, size_t len, bool ownsPointer){
	if(m_bClosing || m_bDestroyed || m_bWaitingForFirstPacket) return;
	
#ifndef _WIN32
	if(m_bSecure){
		SSL_write(m_SSL, data, len);
		FlushSSLWrite();
		if(ownsPointer) delete[] data;
		return;
	}
#endif
	
	WriteRaw(data, len, ownsPointer);
}

void Client::WriteRaw(const char *data, size_t len, bool ownsPointer){
	if(m_bClosing || m_bDestroyed) return;
	
	if(!uv_is_writable((uv_stream_t*) &m_Socket)){
		if(ownsPointer) delete[] data;
		Destroy("unwritable_1");
		return;
	}

	struct CustomWriteRequest {
		uv_write_t req;
		uv_buf_t buf;
		Client *client;
		bool ownsPointer;
	};

	auto request = new CustomWriteRequest();
	request->buf.base = (char*) data;
	request->buf.len = len;
	request->client = this;
	request->ownsPointer = ownsPointer;

	uv_write(&request->req, (uv_stream_t*) &m_Socket, &request->buf, 1, [](uv_write_t* req, int status){
		auto request = (CustomWriteRequest*) req;

		if(status < 0){
			request->client->Destroy("write_failed_1");
		}

		if(request->ownsPointer){
			delete[] request->buf.base;
		}
		delete request;
	});
}

void Client::DestroyPacket(unsigned char *packet){
	WriteRequestPart *part = PacketToWriteRequest(packet);
	if(--part->refCount == 0){
		delete[] (char*)part;
	}
}
