#ifndef MXEVENTMANAGER_H
#define MXEVENTMANAGER_H

#include "decomp.h"
#include "mxpresentationmanager.h"

// VTABLE: LEGO1 0x100dc900
// SIZE 0x2c
class MxEventManager : public MxPresentationManager {
public:
	MxEventManager();
	~MxEventManager() override;

	void Destroy() override;                                             // vtable+18
	virtual MxResult Create(MxU32 p_frequencyMS, MxBool p_createThread); // vtable+28

	// SYNTHETIC: LEGO1 0x100c03d0
	// MxEventManager::`scalar deleting destructor'

private:
	void Init();
	void Destroy(MxBool p_fromDestructor);
};

#endif // MXEVENTMANAGER_H
