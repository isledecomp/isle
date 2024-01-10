#include "mxcore.h"

#include "define.h"

// FUNCTION: LEGO1 0x10001f70
MxResult MxCore::Tickle()
{
	return SUCCESS;
}

// FUNCTION: LEGO1 0x100ae1a0
MxCore::MxCore()
{
	m_id = (MxU32) g_mxcoreCount[0];
	g_mxcoreCount[0]++;
}

// FUNCTION: LEGO1 0x100ae1e0
MxCore::~MxCore()
{
}

// FUNCTION: LEGO1 0x100ae1f0
MxLong MxCore::Notify(MxParam& p_param)
{
	return 0;
}
