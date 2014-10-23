#include "Client.h"
#include "ClientManager.h"
#include <unistd.h>

int main(){
	ClientManager::Init();
	for(;;){
		ClientManager::Run();
		usleep(1000);
	}
	ClientManager::Destroy();
}