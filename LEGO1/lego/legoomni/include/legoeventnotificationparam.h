#ifndef LEGOEVENTNOTIFICATIONPARAM_H
#define LEGOEVENTNOTIFICATIONPARAM_H

#include "mxnotificationparam.h"
#include "mxtypes.h"

#include <stdlib.h>

// VTABLE: LEGO1 0x100d6aa0
class LegoEventNotificationParam : public MxNotificationParam {
public:
	inline LegoEventNotificationParam() : MxNotificationParam(PARAM_NONE, NULL) {}
	inline LegoEventNotificationParam(
		NotificationId p_type,
		MxCore* p_sender,
		MxU8 p_modifier,
		MxS32 p_x,
		MxS32 p_y,
		MxU8 p_key
	)
		: MxNotificationParam(p_type, p_sender), m_modifier(p_modifier), m_x(p_x), m_y(p_y), m_key(p_key), m_unk0x1c(0)
	{
	}

	virtual ~LegoEventNotificationParam() override {} // vtable+0x0 (scalar deleting destructor)
	inline MxU8 GetKey() const { return m_key; }

protected:
	MxU8 m_modifier; // 0x0c
	MxS32 m_x;       // 0x10
	MxS32 m_y;       // 0x14
	MxU8 m_key;      // 0x18
	MxU32 m_unk0x1c; // 0x1c
};

#endif // LEGOEVENTNOTIFICATIONPARAM_H
