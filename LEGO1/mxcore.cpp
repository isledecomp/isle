#include "mxcore.h"

#include "define.h"

// OFFSET: LEGO1 0x10001f70
MxResult MxCore::Tickle()
{
	return SUCCESS;
}

// OFFSET: LEGO1 0x100ae1a0
MxCore::MxCore()
{
	m_id = g_mxcoreCount[0];
	g_mxcoreCount[0]++;
}

// OFFSET: LEGO1 0x100ae1e0
MxCore::~MxCore()
{
}

// OFFSET: LEGO1 0x100ae1f0
MxLong MxCore::Notify(MxParam& p)
{
	return 0;
}
