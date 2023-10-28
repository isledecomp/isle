#ifndef LEGOEVENTNOTIFICATIONPARAM_H
#define LEGOEVENTNOTIFICATIONPARAM_H

#include "mxnotificationparam.h"
#include "mxtypes.h"

// VTABLEADDR 0x100d6aa0
class LegoEventNotificationParam : public MxNotificationParam {
public:
	inline LegoEventNotificationParam() : MxNotificationParam((MxParamType) 0, NULL) {}

	virtual ~LegoEventNotificationParam() override {} // vtable+0x0 (scalar deleting destructor)
	inline MxU8 GetKey() { return m_key; }

protected:
	MxU8 m_modifier; // 0x0c
	MxS32 m_x;       // 0x10
	MxS32 m_y;       // 0x14
	MxU8 m_key;      // 0x18
};

#endif // LEGOEVENTNOTIFICATIONPARAM_H
