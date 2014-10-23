#ifndef WSUV_CLIENT_H
#define WSUV_CLIENT_H

// Note about multi threading:
// This isn't thread-safe if multiple threads can manipulate the same packet at the same time,
// Or if multiple threads can send to the same client at the same time.
// This means you can only use it if one thread "owns" the client at a time.

// If you wanna make this thread safe, then you have to:
// - Add a mutex to protect m_QueuedPackets
// - Make m_bClosing and m_bDestroyed atomic (and change the code according to handle that, using load and compare_and_exchange)

class Client {
public:
	
	void SendPacket(char *packet);
	
	// Creates a packet
	// You then have to send it to clients using SendPacket
	// Then you have to destroy it with DestroyPacket.
	static char *CreatePacket(size_t len, uint8_t opcode = 2);
	
	// Doesn't actually destroy it, only when it's sent. Call it immediatelly after CreatePacket and SendPacket
	// You can't SendPacket if you've already destroyed it with this.
	static void DestroyPacket(char *packet);

	inline void* GetUserData(){ return m_pUserData; }
	inline void  SetUserData(void *v){ m_pUserData = v; }

protected:
	// Note: OnDestroy is only called if OnInit is called
	// OnInit is only called for valid connections
	virtual void OnInit() = 0;
	virtual void OnDestroy() = 0;
	virtual void OnData(const char *data, size_t length) = 0;
	
	void Destroy();
	
private:
	
	Client();
	~Client();
	
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

	void *m_pUserData;
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

extern uint32_t g_iNumCursors;

#endif
