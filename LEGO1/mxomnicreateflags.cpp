#include "mxomnicreateflags.h"

// OFFSET: LEGO1 0x100b0a30
MxOmniCreateFlags::MxOmniCreateFlags()
{
  this->CreateObjectFactory(MX_TRUE);
  this->CreateVariableTable(MX_TRUE);
  this->CreateTickleManager(MX_TRUE);
  this->CreateNotificationManager(MX_TRUE);
  this->CreateVideoManager(MX_TRUE);
  this->CreateSoundManager(MX_TRUE);
  this->CreateMusicManager(MX_TRUE);
  this->CreateEventManager(MX_TRUE);

  this->CreateTimer(MX_TRUE);
  this->CreateStreamer(MX_TRUE);
}
