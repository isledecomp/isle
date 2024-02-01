#include "mxautolocker.h"

// FUNCTION: LEGO1 0x100b8ed0
MxAutoLocker::MxAutoLocker(MxCriticalSection* p_criticalSection)
{
	this->m_criticalSection = p_criticalSection;
	if (this->m_criticalSection != 0) {
		this->m_criticalSection->Enter();
	}
}

// FUNCTION: LEGO1 0x100b8ef0
MxAutoLocker::~MxAutoLocker()
{
	if (this->m_criticalSection != 0) {
		this->m_criticalSection->Leave();
	}
}
