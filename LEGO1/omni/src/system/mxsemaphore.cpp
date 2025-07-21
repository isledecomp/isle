
#include "mxsemaphore.h"

#include "decomp.h"

DECOMP_SIZE_ASSERT(MxSemaphore, 0x08)

// FUNCTION: LEGO1 0x100c87d0
// FUNCTION: BETA10 0x10159260
MxSemaphore::MxSemaphore()
{
	m_hSemaphore = NULL;
}

// FUNCTION: LEGO1 0x100c8800
// FUNCTION: BETA10 0x101592d5
MxResult MxSemaphore::Init(MxU32 p_initialCount, MxU32 p_maxCount)
{
	MxResult result = FAILURE;

	m_hSemaphore = CreateSemaphore(NULL, p_initialCount, p_maxCount, NULL);
	if (!m_hSemaphore) {
		goto done;
	}

	result = SUCCESS;

done:
	return result;
}

// FUNCTION: LEGO1 0x100c8830
// FUNCTION: BETA10 0x10159332
void MxSemaphore::Acquire(MxU32 p_timeoutMS)
{
	WaitForSingleObject(m_hSemaphore, p_timeoutMS);
}

// FUNCTION: BETA10 0x10159385
void MxSemaphore::TryAcquire()
{
	WaitForSingleObject(m_hSemaphore, 0);
}

// FUNCTION: LEGO1 0x100c8850
// FUNCTION: BETA10 0x101593aa
void MxSemaphore::Release(MxU32 p_releaseCount)
{
	ReleaseSemaphore(m_hSemaphore, p_releaseCount, NULL);
}
