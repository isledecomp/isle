#include "mxautolock.h"

#include "mxcriticalsection.h"

#ifdef BETA10
// FUNCTION: BETA10 0x101386f0
MxAutoLock::MxAutoLock(MxCriticalSection* p_criticalSection, const char* filename, int line)
{
	m_criticalSection = p_criticalSection;
	m_currentThreadId = GetCurrentThreadId();

	if (m_criticalSection != NULL) {
		m_criticalSection->Enter(m_currentThreadId, filename, line);
	}
}
#else
// FUNCTION: LEGO1 0x100b8ed0
MxAutoLock::MxAutoLock(MxCriticalSection* p_criticalSection)
{
	m_criticalSection = p_criticalSection;

	if (m_criticalSection != NULL) {
		m_criticalSection->Enter();
	}
}
#endif

// FUNCTION: LEGO1 0x100b8ef0
// FUNCTION: BETA10 0x10138744
MxAutoLock::~MxAutoLock()
{
	if (m_criticalSection != NULL) {
		m_criticalSection->Leave();
	}
}
