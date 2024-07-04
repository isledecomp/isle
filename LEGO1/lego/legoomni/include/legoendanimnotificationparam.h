#ifndef LEGOENDANIMNOTIFICATIONPARAM_H
#define LEGOENDANIMNOTIFICATIONPARAM_H

#include "decomp.h"
#include "mxnotificationparam.h"

// VTABLE: LEGO1 0x100d7e80
// SIZE 0x10
class LegoEndAnimNotificationParam : public MxNotificationParam {
public:
	LegoEndAnimNotificationParam(NotificationId p_type, MxCore* p_sender, MxU32 p_index)
		: MxNotificationParam(p_type, p_sender), m_index(p_index)
	{
	}

	// FUNCTION: LEGO1 0x1004afd0
	MxNotificationParam* Clone() const override
	{
		return new LegoEndAnimNotificationParam(m_type, m_sender, m_index);
	} // vtable+0x04

	MxU32 GetIndex() { return m_index; }

protected:
	MxU32 m_index; // 0x0c
};

// SYNTHETIC: LEGO1 0x1004b080
// LegoEndAnimNotificationParam::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1004b0f0
// LegoEndAnimNotificationParam::~LegoEndAnimNotificationParam

#endif // LEGOENDANIMNOTIFICATIONPARAM_H
