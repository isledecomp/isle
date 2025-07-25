#ifndef MXMAIN_H
#define MXMAIN_H

#include "mxcore.h"
#include "mxcriticalsection.h"
#include "mxstring.h"

class MxAtomSet;
class MxDSAction;
class MxEntity;
class MxEventManager;
class MxMusicManager;
class MxNotificationManager;
class MxNotificationParam;
class MxObjectFactory;
class MxOmniCreateParam;
class MxPresenter;
class MxSoundManager;
class MxStreamer;
class MxStreamController;
class MxTickleManager;
class MxTimer;
class MxVariableTable;
class MxVideoManager;

// VTABLE: LEGO1 0x100dc168
// VTABLE: BETA10 0x101c1c40
// SIZE 0x68
class MxOmni : public MxCore {
public:
	static void DestroyInstance();
	static const char* GetCD();
	static const char* GetHD();
	static MxOmni* GetInstance();
	static MxBool IsSound3D();
	static void SetCD(const char* p_cd);
	static void SetHD(const char* p_hd);
	static void SetSound3D(MxBool p_use3dSound);

	MxOmni();
	~MxOmni() override;

	MxLong Notify(MxParam& p_param) override;                                                 // vtable+0x04
	virtual void Init();                                                                      // vtable+0x14
	virtual MxResult Create(MxOmniCreateParam& p_param);                                      // vtable+0x18
	virtual void Destroy();                                                                   // vtable+0x1c
	virtual MxResult Start(MxDSAction* p_dsAction);                                           // vtable+0x20
	virtual void DeleteObject(MxDSAction& p_dsAction);                                        // vtable+0x24
	virtual MxBool DoesEntityExist(MxDSAction& p_dsAction);                                   // vtable+0x28
	virtual MxResult CreatePresenter(MxStreamController* p_controller, MxDSAction& p_action); // vtable+0x2c
	virtual MxEntity* AddToWorld(const char*, MxS32, MxPresenter*);                           // vtable+0x30
	virtual void NotifyCurrentEntity(const MxNotificationParam& p_param);                     // vtable+0x34
	virtual void Pause();                                                                     // vtable+0x38
	virtual void Resume();                                                                    // vtable+0x3c

	// FUNCTION: LEGO1 0x10058a90
	virtual MxBool IsPaused() { return m_paused; } // vtable+0x40

	static void SetInstance(MxOmni* p_instance);
	static MxBool ActionSourceEquals(MxDSAction* p_action, const char* p_name);

	HWND GetWindowHandle() const { return this->m_windowHandle; }

	// FUNCTION: BETA10 0x10125100
	MxObjectFactory* GetObjectFactory() const { return this->m_objectFactory; }

	// FUNCTION: BETA10 0x10125120
	MxNotificationManager* GetNotificationManager() const { return this->m_notificationManager; }

	// FUNCTION: BETA10 0x10125140
	MxTickleManager* GetTickleManager() const { return this->m_tickleManager; }

	// FUNCTION: BETA10 0x10125160
	MxTimer* GetTimer() const { return this->m_timer; }

	// FUNCTION: BETA10 0x101251a0
	MxStreamer* GetStreamer() const { return this->m_streamer; }

	// FUNCTION: BETA10 0x100e5250
	MxSoundManager* GetSoundManager() const { return this->m_soundManager; }

	// FUNCTION: BETA10 0x1009e860
	MxVideoManager* GetVideoManager() const { return this->m_videoManager; }

	// FUNCTION: BETA10 0x101251c0
	MxVariableTable* GetVariableTable() const { return this->m_variableTable; }

	// FUNCTION: BETA10 0x101251e0
	MxMusicManager* GetMusicManager() const { return this->m_musicManager; }

	// FUNCTION: BETA10 0x10125200
	MxEventManager* GetEventManager() const { return this->m_eventManager; }

	// FUNCTION: BETA10 0x10125180
	MxAtomSet* GetAtomSet() const { return this->m_atomSet; }

	MxLong HandleEndAction(MxParam& p_param);

	// SYNTHETIC: LEGO1 0x100aefd0
	// SYNTHETIC: BETA10 0x10130c90
	// MxOmni::`scalar deleting destructor'

protected:
	static MxOmni* g_instance;

	MxString m_mediaPath;                         // 0x08
	HWND m_windowHandle;                          // 0x18
	MxObjectFactory* m_objectFactory;             // 0x1c
	MxVariableTable* m_variableTable;             // 0x20
	MxTickleManager* m_tickleManager;             // 0x24
	MxNotificationManager* m_notificationManager; // 0x28
	MxVideoManager* m_videoManager;               // 0x2c
	MxSoundManager* m_soundManager;               // 0x30
	MxMusicManager* m_musicManager;               // 0x34
	MxEventManager* m_eventManager;               // 0x38
	MxTimer* m_timer;                             // 0x3c
	MxStreamer* m_streamer;                       // 0x40
	MxAtomSet* m_atomSet;                         // 0x44
	MxCriticalSection m_criticalSection;          // 0x48
	MxBool m_paused;                              // 0x64
};

#endif // MXMAIN_H
