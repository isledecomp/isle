#include "mxomnicreateflags.h"

// FUNCTION: LEGO1 0x100b0a30
MxOmniCreateFlags::MxOmniCreateFlags()
{
	this->CreateObjectFactory(TRUE);
	this->CreateVariableTable(TRUE);
	this->CreateTickleManager(TRUE);
	this->CreateNotificationManager(TRUE);
	this->CreateVideoManager(TRUE);
	this->CreateSoundManager(TRUE);
	this->CreateMusicManager(TRUE);
	this->CreateEventManager(TRUE);

	this->CreateTimer(TRUE);
	this->CreateStreamer(TRUE);
}
