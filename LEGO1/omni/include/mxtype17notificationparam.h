#ifndef MXTYPE17NOTIFICATIONPARAM_H
#define MXTYPE17NOTIFICATIONPARAM_H

#include "decomp.h"
#include "mxnotificationparam.h"

// ??? This type is handled, but seemingly never created and no VTABLE fits
class MxType17NotificationParam : public MxNotificationParam {
public:
	inline MxU32 GetUnknown20() { return m_unk0x20; }
	inline MxU16 GetUnknown28() { return m_unk0x28; }

protected:
	undefined m_unk0xc[0x14];
	MxU32 m_unk0x20;
	undefined4 m_unk0x24;
	MxU16 m_unk0x28;
};

#endif // MXTYPE17NOTIFICATIONPARAM_H
