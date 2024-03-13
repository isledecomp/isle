#include "mxcore.h"

#include <assert.h>

// GLOBAL: LEGO1 0x1010141c
MxU32 MxCore::g_nextCoreId = 0;

// FUNCTION: LEGO1 0x100ae1a0
MxCore::MxCore()
{
	m_id = g_nextCoreId++;
	assert(g_nextCoreId);
}

// FUNCTION: LEGO1 0x100ae1e0
MxCore::~MxCore()
{
}

// FUNCTION: LEGO1 0x100ae1f0
MxLong MxCore::Notify(MxParam& p_param)
{
	assert(0);
	return 0;
}
