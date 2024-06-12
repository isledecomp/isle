#include "mxobjectfactory.h"

#include "decomp.h"
#include "mxcompositepresenter.h"
#include "mxeventpresenter.h"
#include "mxflcpresenter.h"
#include "mxloopingflcpresenter.h"
#include "mxloopingmidipresenter.h"
#include "mxloopingsmkpresenter.h"
#include "mxmidipresenter.h"
#include "mxpresenter.h"
#include "mxsmkpresenter.h"
#include "mxstillpresenter.h"
#include "mxvideopresenter.h"
#include "mxwavepresenter.h"

DECOMP_SIZE_ASSERT(MxObjectFactory, 0x38); // 100af1db

// FUNCTION: LEGO1 0x100b0d80
MxObjectFactory::MxObjectFactory()
{
#define X(V) m_id##V = MxAtomId(#V, e_exact);
	FOR_MXOBJECTFACTORY_OBJECTS(X)
#undef X
}

// FUNCTION: LEGO1 0x100b12c0
MxCore* MxObjectFactory::Create(const char* p_name)
{
	MxCore* object = NULL;
	MxAtomId atom(p_name, e_exact);

	if (0) {
	}
#define X(V)                                                                                                           \
	else if (m_id##V == atom)                                                                                          \
	{                                                                                                                  \
		object = new V;                                                                                                \
	}
	FOR_MXOBJECTFACTORY_OBJECTS(X)
#undef X
	return object;
}

// FUNCTION: LEGO1 0x100b1a30
void MxObjectFactory::Destroy(MxCore* p_object)
{
	delete p_object;
}
