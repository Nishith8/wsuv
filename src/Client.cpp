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
#include <thread>
#include <cstring>
#include "sha1.h"
#include "base64.h"
#include "ClientManager.h"

struct WriteRequestPart;
struct WriteRequest {
	uv_write_t req;
	WriteRequestPart *part;
	Client *client;
};

struct WriteRequestPart {
	uv_buf_t buf;
	int refCount;
};

extern std::thread::id g_WSUV_MainThreadID;
extern std::vector<Client*> g_WSUV_Clients;

struct DataFrameHeader {
	char data[2];

	DataFrameHeader(){ data[0] = 0; data[1] = 0; }

	void fin(bool v){ data[0] &= ~(1 << 7); data[0] |= v << 7; }
	void rsv1(bool v){ data[0] &= ~(1 << 6); data[0] |= v << 6; }
	void rsv2(bool v){ data[0] &= ~(1 << 5); data[0] |= v << 5; }
	void rsv3(bool v){ data[0] &= ~(1 << 4); data[0] |= v << 4; }
	void mask(bool v){ data[1] &= ~(1 << 7); data[1] |= v << 7; }
	void opcode(uint8_t v){
		data[0] &= ~0x0F;
		data[0] |= v & 0x0F;
	}

	void len(uint8_t v){
		data[1] &= ~0x7F;
		data[1] |= v & 0x7F;
	}

	bool fin(){  return (data[0] >> 7) & 1; }
	bool rsv1(){ return (data[0] >> 6) & 1; }
	bool rsv2(){ return (data[0] >> 5) & 1; }
	bool rsv3(){ return (data[0] >> 4) & 1; }
	bool mask(){ return (data[1] >> 7) & 1; }

	uint8_t opcode(){
		return data[0] & 0x0F;
	}

	uint8_t len(){
		return data[1] & 0x7F;
	}
};

static_assert(sizeof(DataFrameHeader) == 2, "DataFrame basic header must have 4 bytes (we only use 2 though)");

Client::Client(){
	m_iBufferPos = 0;
	m_bHasCompletedHandshake = false;
	m_bClosing = false;
	m_bDestroyed = false;
	
	for(size_t i = 0; i < g_WSUV_Clients.size(); +i){
		if(g_WSUV_Clients[i] != nullptr) continue;
		g_WSUV_Clients[i] = this;
		goto AddedMe;
	}
	
	g_WSUV_Clients.push_back(this);
	
	AddedMe:;
}

Client::~Client(){
	m_bClosing = true;
	m_bDestroyed = true;
	
	for(size_t i = 0; i < g_WSUV_Clients.size(); +i){
		if(g_WSUV_Clients[i] != this) continue;
		g_WSUV_Clients[i] = nullptr;
		break;
	}
	
	for(auto &d : m_Frames){
		delete[] d.data;
	}

	for(char *packet : m_QueuedPackets){
		WriteRequestPart *part = (WriteRequestPart*)(packet - sizeof(WriteRequestPart) - 10);
		if(--part->refCount == 0){
			delete part;
		}
	}
}

void Client::Destroy(){
	m_bClosing = true;

	if(m_bDestroyed) return;
	m_bDestroyed = true;
	
	OnDestroy();
	
	uv_close((uv_handle_t*) &m_Socket, [](uv_handle_t* handle){
		Client *client = (Client*) handle->data;
		delete client;
	});
}


void Client::OnSocketData(char *data, size_t len){
	if(m_bClosing || m_bDestroyed) return;

	// This should still give us a byte to put a null terminator
	// during the http phase
	if(m_iBufferPos + len >= sizeof(m_Buffer)){
		Destroy();
		return;
	}

	memcpy(&m_Buffer[m_iBufferPos], data, len);
	m_iBufferPos += len;
	m_Buffer[m_iBufferPos] = 0;

	if(!m_bHasCompletedHandshake){
		// Haven't completed the header yet
		if(strstr(m_Buffer, "\r\n\r\n") == nullptr) return;
		
		const char *str = m_Buffer;

		bool badHeader = false;

		// First line is a weird one, ignore it
		str = strstr(m_Buffer, "\r\n") + 2;

		bool hasUpgradeHeader = false;
		bool hasConnectionHeader = false;
		bool sendMyVersion = false;
		bool hasVersionHeader = false;
		std::string securityKey;
		
		for(;;){
			auto nextLine = strstr(str, "\r\n");
			// This means that we have finished parsing the headers
			if(nextLine == str){
				break;
			}
			
			if(nextLine == nullptr){
				badHeader = true;
				break;
			}
			
			auto colonPos = strstr(str, ":");
			if(colonPos == nullptr || colonPos > nextLine){
				badHeader = true;
				break;
			}

			auto keyPos = str;
			ssize_t keyLength = colonPos - keyPos;
			auto valuePos = colonPos + 1;
			while(*valuePos == ' ') ++valuePos;
			ssize_t valueLength = nextLine - valuePos;

			if(strncmp("Upgrade", keyPos, keyLength) == 0){
				hasUpgradeHeader = true;
				if(strncmp("websocket", valuePos, valueLength) != 0){
					badHeader = true;
					break;
				}
			}else if(strncmp("Connection", keyPos, keyLength) == 0){
				hasConnectionHeader = true;
				auto uppos = strstr(valuePos, "Upgrade");
				if(uppos == nullptr || uppos > nextLine){
					badHeader = true;
					break;
				}
			} else if(strncmp("Sec-WebSocket-Key", keyPos, keyLength) == 0){
				securityKey = std::string(valuePos, valueLength);
			}else if(strncmp("Sec-WebSocket-Version", keyPos, keyLength) == 0){
				hasVersionHeader = true;
				if(strncmp("13", valuePos, valueLength) != 0){
					sendMyVersion = true;
				}
			}else if(strncmp("Origin", keyPos, keyLength) == 0){
				// If you want to filter stuff that doesn't come from your origin, change the url
				/*
				if(strncmp("http://localhost", valuePos, valueLength) != 0 && strncmp("http://example.com", valuePos, valueLength) != 0){
					badHeader = true;
					break;
				}*/
			}

			str = nextLine + 2;
		}

		if(!hasUpgradeHeader) badHeader = true;
		if(!hasConnectionHeader) badHeader = true;
		if(!hasVersionHeader) badHeader = true;


#define EXPAND_LITERAL(x) x, strlen(x)

		if(badHeader){
			SendRawAndDestroy(EXPAND_LITERAL("HTTP/1.1 400 Bad Request\r\n\r\n"));
			return;
		}

		securityKey += "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
		unsigned char hash[20];
		sha1::calc(securityKey.data(), securityKey.size(), hash);
		auto solvedHash = base64_encode(hash, sizeof(hash));
		auto allocatedHash = new char[solvedHash.size()];
		memcpy(allocatedHash, solvedHash.data(), solvedHash.size());

		SendRaw(EXPAND_LITERAL("HTTP/1.1 101 Switching Protocols\r\n"));
		SendRaw(EXPAND_LITERAL("Upgrade: websocket\r\n"));
		SendRaw(EXPAND_LITERAL("Connection: Upgrade\r\n"));
		if(sendMyVersion){
			SendRaw(EXPAND_LITERAL("Sec-WebSocket-Version: 13\r\n"));

		}
		SendRaw(EXPAND_LITERAL("Sec-WebSocket-Accept: "));
		SendRaw(allocatedHash, solvedHash.size(), true);
		SendRaw(EXPAND_LITERAL("\r\n\r\n"));

		if(!sendMyVersion){
			m_bHasCompletedHandshake = true;

			// Reset buffer
			m_iBufferPos = 0;

			OnInit();
		}

#undef EXPAND_LITERAL
		return;
	}
	
	while(m_iBufferPos > 0){
		// Not enough to read the header
		if(m_iBufferPos < 2) return;

		auto &header = *(DataFrameHeader*) m_Buffer;
	
		if(header.rsv1() || header.rsv2() || header.rsv3()){
			Destroy();
			return;
		}

		char *curPosition = m_Buffer + 2;

		size_t frameLength = header.len();
		if(frameLength == 126){
			if(m_iBufferPos < 4) return;
			frameLength = *(uint16_t*) curPosition;
			curPosition += 2;
		}else if(frameLength == 127){
			if(m_iBufferPos < 10) return;
			frameLength = *(uint64_t*) curPosition;
			curPosition += 8;
		}

		auto amountLeft = m_iBufferPos - (curPosition - m_Buffer);
		const char *maskKey = nullptr;
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

				char *allFrames = new char[totalLength];
				size_t allFramesPos = 0;
				for(DataFrame &frame : m_Frames){
					memcpy(allFrames + allFramesPos, frame.data, frame.len);
					allFramesPos += frame.len;
					delete[] frame.data;
				}

				ProcessDataFrame(m_Frames[0].opcode, allFrames, totalLength);
			
				m_Frames.clear();
				delete[] allFrames;
			}
		
		}

		size_t consumed = (curPosition - m_Buffer) + frameLength;
		memmove(m_Buffer, &m_Buffer[consumed], m_iBufferPos - consumed);
		m_iBufferPos -= consumed;
	}
}

void Client::ProcessDataFrame(uint8_t opcode, const char *data, size_t len){
	//printf("Received frame opcode %d\n", (int) opcode);
	if(opcode == 9){
		// Ping
		char *packet = CreatePacket(len, 10);
		memcpy(packet, data, len);
		SendPacket(packet);
		DestroyPacket(packet);
		return;
	}

	if(opcode == 8){
		// Close
		Destroy();
		return;
	}

	if(opcode == 1 || opcode == 2){
		OnData(data, len);
		return;
	}
}

char *Client::CreatePacket(size_t len, uint8_t opcode){
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

	char *data = new char[sizeof(WriteRequestPart) + 10 + len];

	WriteRequestPart *req = (WriteRequestPart*) data;
	auto headerStart = (data + sizeof(WriteRequestPart) + 10 - headerLen);
	req->buf.len = headerLen + len;
	req->buf.base = headerStart;
	req->refCount = 1;

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

	return data + sizeof(WriteRequestPart) + 10;
}

void Client::CheckQueuedPackets(){
	for(char *packet : m_QueuedPackets){
		WriteRequestPart *part = (WriteRequestPart*)(packet - sizeof(WriteRequestPart) - 10);
		--part->refCount;
		SendPacket(packet);
	}

	m_QueuedPackets.clear();
}

void Client::SendPacket(char *packet){
	if(m_bClosing || m_bDestroyed) return;

	WriteRequestPart *part = (WriteRequestPart*)(packet - sizeof(WriteRequestPart) - 10);
	++part->refCount;
	
	
	if(std::this_thread::get_id() != g_WSUV_MainThreadID){
		m_QueuedPackets.push_back(packet);
		return;
	}


	//printf("Sending packet with length %d\n", (int) part->buf.len);

	if(!uv_is_writable((uv_stream_t*) &m_Socket)){
		if(--part->refCount == 0){
			delete part;
		}

		Destroy();
		return;
	}

	WriteRequest *req = new WriteRequest;
	req->part = part;
	req->client = this;

	uv_write(&req->req, (uv_stream_t*) &m_Socket, &part->buf, 1, [](uv_write_t* req2, int status){
		WriteRequest *req = (WriteRequest *) req2;
		if(status < 0){
			req->client->Destroy();
		}

		if(--req->part->refCount == 0){
			delete req->part;
		}
		delete req;
	});
}

void Client::SendRawAndDestroy(const char *data, size_t len){
	if(m_bClosing || m_bDestroyed) return;
	
	if(!uv_is_writable((uv_stream_t*) &m_Socket)){
		Destroy();
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
		request->client->Destroy();
		delete request;
	});
}

void Client::SendRaw(const char *data, size_t len, bool ownsPointer){
	if(m_bClosing || m_bDestroyed) return;
	
	if(!uv_is_writable((uv_stream_t*) &m_Socket)){
		if(ownsPointer) delete[] data;
		Destroy();
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
			request->client->Destroy();
		}

		if(request->ownsPointer){
			delete[] request->buf.base;
		}
		delete request;
	});
}

void Client::DestroyPacket(char *packet){
	WriteRequestPart *part = (WriteRequestPart*)(packet - sizeof(WriteRequestPart) - 10);
	if(--part->refCount == 0){
		delete part;
	}
}
