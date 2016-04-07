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

#ifndef WSUV_CLIENT_H
#define WSUV_CLIENT_H


class ClientManager;
class Client {
public:
	// Closes the connection
	void Destroy();
	
	void SendPacket(unsigned char *packet);

	inline const std::string& GetIP(){
		assert(!m_IP.empty()); // In the constructor it's still empty, don't use this, call it OnInit
		return m_IP;
	}

	// Creates a packet
	// You then have to send it to clients using SendPacket
	// Then you have to destroy it with DestroyPacket.
	static unsigned char *CreatePacket(size_t len, uint8_t opcode = 2);
	static unsigned char *CreatePacket(const std::string &str){
		auto packet = CreatePacket(str.size());
		memcpy(packet, str.data(), str.size());
		return packet;
	}
	
	// Doesn't actually destroy it, only when it's sent. Call it immediatelly after CreatePacket and SendPacket
	// You can't SendPacket if you've already destroyed it with this.
	static void DestroyPacket(unsigned char *packet);
	
protected:
	
	Client();
	virtual ~Client();
	
	virtual void OnInit() = 0;
	virtual void OnDestroy() = 0;
	virtual void OnData(const unsigned char *data, size_t length) = 0;
	
private:
	
	struct DataFrame {
		uint8_t opcode;
		char  *data;
		size_t len;
	};

	void OnSocketData(unsigned char *data, size_t len);
	void OnSocketData2(unsigned char *data, size_t len);
	void WriteAndDestroy(const char *data, size_t len);
	void Write(const char *data, size_t len, bool ownsPointer = false);
	void WriteRaw(const char *data, size_t len, bool ownsPointer);
	void ProcessDataFrame(uint8_t opcode, const unsigned char *data, size_t len);
	void CheckQueuedPackets();
	
#ifndef _WIN32
	void HandleSSLError(int err);
	void FlushSSLWrite();
#endif

	uv_tcp_t m_Socket;
	
	std::string m_IP;
	bool m_bWaitingForFirstPacket = true;
#ifndef _WIN32
	bool m_bSecure = false;
	bool m_bDoingSSLHandshake = false;
	SSL *m_SSL = nullptr;
	BIO *m_SSL_read = nullptr;
	BIO *m_SSL_write = nullptr;
#endif
	bool m_bClosing = false;
	bool m_bDestroyed = false;
	bool m_bHasCompletedHandshake = false;
	std::vector<DataFrame> m_Frames;
	std::vector<unsigned char*> m_QueuedPackets;
	size_t m_iBufferPos = 0;
	unsigned char m_Buffer[16 * 1024]; // Increase the size if needed

	friend ClientManager;
};

#endif
