#include "mxcore.h"

#include <assert.h>

// GLOBAL: LEGO1 0x1010141c
// GLOBAL: BETA10 0x10201f88
MxU32 MxCore::g_nextCoreId = 0;

// FUNCTION: LEGO1 0x100ae1a0
// FUNCTION: BETA10 0x1012c020
MxCore::MxCore() {
	m_id = g_nextCoreId++;
	assert(g_nextCoreId);
}

// FUNCTION: LEGO1 0x100ae1e0
// FUNCTION: BETA10 0x1012c077
MxCore::~MxCore()
{
}

// FUNCTION: LEGO1 0x100ae1f0
// FUNCTION: BETA10 0x1012c096
MxLong MxCore::Notify(MxParam& p_param)
{
	assert(0);
	return 0;
}
