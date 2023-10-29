#ifndef MXTYPE17NOTIFICATIONPARAM_H
#define MXTYPE17NOTIFICATIONPARAM_H

#include "decomp.h"
#include "mxnotificationparam.h"

// ??? This type is handled, but seemingly never created and no VTABLE fits
class MxType17NotificationParam : public MxNotificationParam {
public:
	inline MxU32 GetUnknown20() { return m_unk20; }
	inline MxU16 GetUnknown28() { return m_unk28; }

protected:
	undefined m_unkc[0x14];
	MxU32 m_unk20;
	undefined4 m_unk24;
	MxU16 m_unk28;
};

#endif // MXTYPE17NOTIFICATIONPARAM_H
