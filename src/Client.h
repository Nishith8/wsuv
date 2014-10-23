#ifndef WSUV_CLIENT_H
#define WSUV_CLIENT_H

#include <cstdint>
#include <vector>
#include "uv.h"

// Note about multi threading:
// This isn't thread-safe if multiple threads can manipulate the same packet at the same time,
// or if multiple threads can send to the same client at the same time.
// This means you can only use it if one thread "owns" the client at a time.

// If you wanna make this thread safe, then you have to:
// - Add a mutex to protect m_QueuedPackets
// - Make m_bClosing and m_bDestroyed atomic (and change the code according to handle that, using load and compare_and_exchange)
// - Make refcount atomic in the WriteRequest struct
// Maybe more stuff, but anyways, you shouldn't do that.

class ClientManager;
class Client {
public:
	
	// Closes the connection
	void Destroy();
	
	void SendPacket(char *packet);
	
	// Creates a packet
	// You then have to send it to clients using SendPacket
	// Then you have to destroy it with DestroyPacket.
	static char *CreatePacket(size_t len, uint8_t opcode = 2);
	
	// Doesn't actually destroy it, only when it's sent. Call it immediatelly after CreatePacket and SendPacket
	// You can't SendPacket if you've already destroyed it with this.
	static void DestroyPacket(char *packet);
	
protected:
	
	Client();
	~Client();
	
	// Note: OnDestroy is only called if OnInit is called
	// OnInit is only called for valid connections
	virtual void OnInit() = 0;
	virtual void OnDestroy() = 0;
	virtual void OnData(const char *data, size_t length) = 0;
	
private:
	
	struct DataFrame {
		uint8_t opcode;
		char  *data;
		size_t len;
	};

	void OnSocketData(char *data, size_t len);
	void SendRawAndDestroy(const char *data, size_t len);
	void SendRaw(const char *data, size_t len, bool ownsPointer = false);
	void ProcessDataFrame(uint8_t opcode, const char *data, size_t len);
	void CheckQueuedPackets();

	uv_tcp_t m_Socket;
	bool m_bClosing;
	bool m_bDestroyed;
	bool m_bHasCompletedHandshake;
	std::vector<DataFrame> m_Frames;
	std::vector<char*> m_QueuedPackets;
	size_t m_iBufferPos;
	char m_Buffer[16 * 1024]; // Increase the size if needed

	friend ClientManager;
};

#endif
