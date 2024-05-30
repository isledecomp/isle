#ifndef MXTICKLETHREAD_H
#define MXTICKLETHREAD_H

#include "mxthread.h"

// VTABLE: LEGO1 0x100dc6d8
// SIZE 0x20
class MxTickleThread : public MxThread {
public:
	MxTickleThread(MxCore* p_target, MxS32 p_frequencyMS);

	MxResult Run() override;

	// SYNTHETIC: LEGO1 0x100b8c20
	// MxTickleThread::`scalar deleting destructor'

private:
	MxS32 m_frequencyMS; // 0x1c
};

#endif // MXTICKLETHREAD_H
