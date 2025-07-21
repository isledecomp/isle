#ifndef MXPRESENTATIONMANAGER_H
#define MXPRESENTATIONMANAGER_H

#include "mxcore.h"
#include "mxcriticalsection.h"
#include "mxpresenterlist.h"
#include "mxtypes.h"

class MxThread;

// VTABLE: LEGO1 0x100dc6b0
// VTABLE: BETA10 0x101c2318
// SIZE 0x2c
class MxPresentationManager : public MxCore {
public:
	MxPresentationManager();
	~MxPresentationManager() override;

	MxResult Tickle() override;                                 // vtable+08
	virtual MxResult Create();                                  // vtable+14
	virtual void Destroy();                                     // vtable+18
	virtual void RegisterPresenter(MxPresenter& p_presenter);   // vtable+1c
	virtual void UnregisterPresenter(MxPresenter& p_presenter); // vtable+20
	virtual void StopPresenters();                              // vtable+24

	MxResult Init();

	// SYNTHETIC: LEGO1 0x100b8540
	// SYNTHETIC: BETA10 0x10144db0
	// MxPresentationManager::`scalar deleting destructor'

protected:
	MxPresenterList* m_presenters;       // 0x08
	MxThread* m_thread;                  // 0x0c
	MxCriticalSection m_criticalSection; // 0x10
};

#endif // MXPRESENTATIONMANAGER_H
