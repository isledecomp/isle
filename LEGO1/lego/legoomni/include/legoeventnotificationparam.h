#ifndef LEGOEVENTNOTIFICATIONPARAM_H
#define LEGOEVENTNOTIFICATIONPARAM_H

#include "mxnotificationparam.h"
#include "mxtypes.h"
#include "roi/legoroi.h"

#include <stdlib.h>

// VTABLE: LEGO1 0x100d6aa0
// SIZE 0x20
class LegoEventNotificationParam : public MxNotificationParam {
public:
	enum {
		c_lButtonState = 0x01,
		c_rButtonState = 0x02,
		c_modKey1 = 0x04,
		c_modKey2 = 0x08,
	};

	// FUNCTION: LEGO1 0x10028690
	MxNotificationParam* Clone() override
	{
		LegoEventNotificationParam* clone =
			new LegoEventNotificationParam(m_type, m_sender, m_modifier, m_x, m_y, m_key);
		clone->m_roi = m_roi;
		return clone;
	} // vtable+0x04

	inline LegoEventNotificationParam() : MxNotificationParam(c_notificationType0, NULL) {}
	inline LegoEventNotificationParam(
		NotificationId p_type,
		MxCore* p_sender,
		MxU8 p_modifier,
		MxS32 p_x,
		MxS32 p_y,
		MxU8 p_key
	)
		: MxNotificationParam(p_type, p_sender), m_modifier(p_modifier), m_x(p_x), m_y(p_y), m_key(p_key), m_roi(NULL)
	{
	}

	inline MxU8 GetModifier() { return m_modifier; }
	inline MxU8 GetKey() const { return m_key; }

	// FUNCTION: LEGO1 0x10012190
	inline MxS32 GetX() const { return m_x; }

	// FUNCTION: LEGO1 0x100121a0
	inline MxS32 GetY() const { return m_y; }

	inline void SetROI(LegoROI* p_roi) { m_roi = p_roi; }
	inline void SetModifier(MxU8 p_modifier) { m_modifier = p_modifier; }
	inline void SetKey(MxU8 p_key) { m_key = p_key; }
	inline void SetX(MxS32 p_x) { m_x = p_x; }
	inline void SetY(MxS32 p_y) { m_y = p_y; }

protected:
	MxU8 m_modifier; // 0x0c
	MxS32 m_x;       // 0x10
	MxS32 m_y;       // 0x14
	MxU8 m_key;      // 0x18
	LegoROI* m_roi;  // 0x1c
};

// SYNTHETIC: LEGO1 0x10028770
// LegoEventNotificationParam::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100287e0
// LegoEventNotificationParam::~LegoEventNotificationParam

#endif // LEGOEVENTNOTIFICATIONPARAM_H
