#include "mxautolock.h"

#include "mxcriticalsection.h"

// FUNCTION: LEGO1 0x100b8ed0
MxAutoLock::MxAutoLock(MxCriticalSection* p_criticalSection)
{
	m_criticalSection = p_criticalSection;

	if (m_criticalSection != NULL) {
		m_criticalSection->Enter();
	}
}

// FUNCTION: LEGO1 0x100b8ef0
MxAutoLock::~MxAutoLock()
{
	if (m_criticalSection != NULL) {
		m_criticalSection->Leave();
	}
}
