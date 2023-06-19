#ifndef MXOMNI_H
#define MXOMNI_H

#include "mxvariabletable.h"
#include "mxticklemanager.h"
#include "legoomni.h"
#include "mxresult.h"
#include "mxomnicreateparam.h"
#include "mxomnicreateflags.h"
#include "mxtimer.h"

class MxOmni : public MxCore
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
  static MxOmni* m_instance;

  MxString m_mediaPath; // 0x8
  HWND *m_windowHandle; // 0x18;
  MxObjectFactory *m_objectFactory; // 0x1C
  MxVariableTable* m_variableTable; //0x20
  MxTickleManager* m_tickleManager; //0x24
  MxNotificationManager* m_notificationManager; //0x28
  MxVideoManager *m_videoManager; //0x2C
  MxSoundManager* m_soundManager; //0x30
  MxMusicManager* m_musicManager; //0x34
  MxEventManager* m_eventManager; //0x38
  MxTimer* m_timer; //0x3C
  MxStreamer* m_streamer; //0x40

  char unknown44[0x4]; // 0x44

  MxCriticalSection m_criticalsection; // 0x48

  char unknown64[0x4]; // 0x64

};

#endif // MXOMNI_H
