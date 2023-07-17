#ifndef MXOMNI_H
#define MXOMNI_H

#include "mxcriticalsection.h"
#include "mxeventmanager.h"
#include "mxmusicmanager.h"
#include "mxnotificationmanager.h"
#include "mxobjectfactory.h"
#include "mxomnicreateflags.h"
#include "mxomnicreateparam.h"
#include "mxsoundmanager.h"
#include "mxstreamer.h"
#include "mxticklemanager.h"
#include "mxtimer.h"
#include "mxvariabletable.h"
#include "mxvideomanager.h"

// VTABLE 0x100dc168
// SIZE 0x68
class MxOmni : public MxCore
{
public:
  __declspec(dllexport) static void DestroyInstance();
  __declspec(dllexport) static const char *GetCD();
  __declspec(dllexport) static const char *GetHD();
  __declspec(dllexport) static MxOmni *GetInstance();
  __declspec(dllexport) static MxBool IsSound3D();
  __declspec(dllexport) static void SetCD(const char *p_cd);
  __declspec(dllexport) static void SetHD(const char *p_hd);
  __declspec(dllexport) static void SetSound3D(MxBool p_3dsound);

  MxOmni();
  virtual ~MxOmni() override;

  virtual MxLong Notify(MxParam &p); // vtable+04
  virtual void Init(); // vtable+14
  virtual MxResult Create(MxOmniCreateParam &p); // vtable+18
  virtual void Destroy(); // vtable+1c
  static void SetInstance(MxOmni* instance);
  MxObjectFactory* GetObjectFactory() const { return this->m_objectFactory; }
  MxNotificationManager* GetNotificationManager() const { return this->m_notificationManager; }
  MxTickleManager* GetTickleManager() const { return this->m_tickleManager; }
  MxTimer* GetTimer() const { return this->m_timer; }
  MxStreamer* GetStreamer() const { return this->m_streamer; }
  MxSoundManager* GetSoundManager() const { return this->m_soundManager; }
  MxVideoManager* GetVideoManager() const { return this->m_videoManager; }
  MxVariableTable* GetVariableTable() const { return this->m_variableTable; }
  MxMusicManager* GetMusicManager() const { return this->m_musicManager; }
  MxEventManager* GetEventManager() const { return this->m_eventManager; }

  // FIXME: put this in the correct spot, just a hack for LegoInputManager
  HWND* GetWindowHandle() const { return this->m_windowHandle; }
protected:
  static MxOmni* g_instance;

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

  int m_unk44; // 0x44

  MxCriticalSection m_criticalsection; // 0x48

  unsigned char m_unk64; // 0x64
};
__declspec(dllexport) MxTickleManager * TickleManager();
__declspec(dllexport) MxTimer * Timer();
__declspec(dllexport) MxStreamer * Streamer();
__declspec(dllexport) MxSoundManager * MSoundManager();
__declspec(dllexport) MxVariableTable * VariableTable();
__declspec(dllexport) MxMusicManager * MusicManager();
__declspec(dllexport) MxEventManager * EventManager();
__declspec(dllexport) MxNotificationManager * NotificationManager();
MxVideoManager * MVideoManager();

#endif // MXOMNI_H
