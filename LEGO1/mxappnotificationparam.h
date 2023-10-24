#ifndef MXAPPNOTIFICATIONPARAM_H
#define MXAPPNOTIFICATIONPARAM_H

#include "decomp.h"
#include "mxnotificationparam.h"

// VTABLE 0x100d6aa0
class MxAppNotificationParam : public MxNotificationParam {
public:
	inline MxAppNotificationParam() : MxNotificationParam((MxParamType) 0, NULL) {}

	virtual ~MxAppNotificationParam() override {} // vtable+0x0 (scalar deleting destructor)
	inline MxU8 GetUnknown18() { return m_unk18; }

protected:
	undefined m_unkc[0xc];
	MxU8 m_unk18;
};

#endif // MXAPPNOTIFICATIONPARAM_H