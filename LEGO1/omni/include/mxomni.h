#ifndef MXOMNI_H
#define MXOMNI_H

#include "mxcore.h"
#include "mxcriticalsection.h"
#include "mxstring.h"

class MxAtomId;
class MxAtomIdCounterSet;
class MxDSAction;
class MxEventManager;
class MxMusicManager;
class MxNotificationManager;
class MxNotificationParam;
class MxObjectFactory;
class MxOmniCreateParam;
class MxPresenter;
class MxSoundManager;
class MxStreamer;
class MxTickleManager;
class MxTimer;
class MxVariableTable;
class MxVideoManager;
class MxEntity;
class MxStreamController;

// VTABLE: LEGO1 0x100dc168
// SIZE 0x68
class MxOmni : public MxCore {
public:
	__declspec(dllexport) static void DestroyInstance();
	__declspec(dllexport) static const char* GetCD();
	__declspec(dllexport) static const char* GetHD();
	__declspec(dllexport) static MxOmni* GetInstance();
	__declspec(dllexport) static MxBool IsSound3D();
	__declspec(dllexport) static void SetCD(const char* p_cd);
	__declspec(dllexport) static void SetHD(const char* p_hd);
	__declspec(dllexport) static void SetSound3D(MxBool p_use3dSound);

	MxOmni();
	virtual ~MxOmni() override;

	virtual MxLong Notify(MxParam& p_param) override;                                         // vtable+04
	virtual void Init();                                                                      // vtable+14
	virtual MxResult Create(MxOmniCreateParam& p_param);                                      // vtable+18
	virtual void Destroy();                                                                   // vtable+1c
	virtual MxResult Start(MxDSAction* p_dsAction);                                           // vtable+20
	virtual void DeleteObject(MxDSAction& p_dsAction);                                        // vtable+24
	virtual MxBool DoesEntityExist(MxDSAction& p_dsAction);                                   // vtable+28
	virtual MxResult CreatePresenter(MxStreamController* p_controller, MxDSAction& p_action); // vtable+2c
	virtual MxEntity* FindWorld(const char*, MxS32, MxPresenter*);                            // vtable+30
	virtual void NotifyCurrentEntity(MxNotificationParam* p_param);                           // vtable+34
	virtual void StartTimer();                                                                // vtable+38
	virtual void StopTimer();                                                                 // vtable+3c
	virtual MxBool IsTimerRunning();                                                          // vtable+40

	static void SetInstance(MxOmni* p_instance);
	static MxBool FUN_100b06b0(MxDSAction* p_action, const char* p_name);

	HWND GetWindowHandle() const { return this->m_windowHandle; }
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
	MxAtomIdCounterSet* GetAtomIdCounterSet() const { return this->m_atomIdCounterSet; }
	MxLong HandleActionEnd(MxParam& p_param);

protected:
	static MxOmni* g_instance;

	MxString m_mediaPath;                         // 0x8
	HWND m_windowHandle;                          // 0x18
	MxObjectFactory* m_objectFactory;             // 0x1C
	MxVariableTable* m_variableTable;             // 0x20
	MxTickleManager* m_tickleManager;             // 0x24
	MxNotificationManager* m_notificationManager; // 0x28
	MxVideoManager* m_videoManager;               // 0x2C
	MxSoundManager* m_soundManager;               // 0x30
	MxMusicManager* m_musicManager;               // 0x34
	MxEventManager* m_eventManager;               // 0x38
	MxTimer* m_timer;                             // 0x3C
	MxStreamer* m_streamer;                       // 0x40
	MxAtomIdCounterSet* m_atomIdCounterSet;       // 0x44
	MxCriticalSection m_criticalsection;          // 0x48
	MxBool m_timerRunning;                        // 0x64
};

__declspec(dllexport) MxTickleManager* TickleManager();
__declspec(dllexport) MxTimer* Timer();
__declspec(dllexport) MxStreamer* Streamer();
__declspec(dllexport) MxSoundManager* MSoundManager();
__declspec(dllexport) MxVariableTable* VariableTable();
__declspec(dllexport) MxMusicManager* MusicManager();
__declspec(dllexport) MxEventManager* EventManager();
__declspec(dllexport) MxNotificationManager* NotificationManager();

MxVideoManager* MVideoManager();
MxAtomIdCounterSet* AtomIdCounterSet();
MxObjectFactory* ObjectFactory();
void DeleteObject(MxDSAction& p_dsAction);
void DeleteObjects(MxAtomId* p_id, MxS32 p_first, MxS32 p_last);

#endif // MXOMNI_H
