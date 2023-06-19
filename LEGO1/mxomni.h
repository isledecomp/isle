#ifndef MXOMNI_H
#define MXOMNI_H

#include "mxvariabletable.h"
#include "mxticklemanager.h"
#include "legoomni.h"
#include "mxresult.h"
#include "mxomnicreateparam.h"
#include "mxomnicreateflags.h"
#include "mxtimer.h"


class MxOmni
{
public:
  __declspec(dllexport) static void DestroyInstance();
  __declspec(dllexport) static const char *GetCD();
  __declspec(dllexport) static const char *GetHD();
  __declspec(dllexport) static MxOmni *GetInstance();
  __declspec(dllexport) static unsigned char IsSound3D();
  __declspec(dllexport) static void SetCD(const char *s);
  __declspec(dllexport) static void SetHD(const char *s);
  __declspec(dllexport) static void SetSound3D(unsigned char);
  
  MxResult MxOmni::Create(const MxOmniCreateParam &p);

  MxTimer* GetTimer() const { return this->m_Timer; } 

private:
  static MxOmni* m_instance; // INCORRECT, PLACEHOLDER
  char m_unknown[0x10];
  MxVariableTable* m_variabletable; //0x20
  MxTickleManager* m_ticklemanager; //0x24
  MxNotificationManager* m_notificationmanager; //0x28
  char m_unknown2[0x4]; //0x2C
  MxSoundManager* m_soundmanager; //0x30
  MxMusicManager* m_musicmanager; //0x34
  MxEventManager* m_eventmanager; //0x38
  MxTimer* m_Timer; //0x3C
  MxStreamer* m_streamer; //0x40
};
