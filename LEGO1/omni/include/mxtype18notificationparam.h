#ifndef MXTYPE18NOTIFICATIONPARAM_H
#define MXTYPE18NOTIFICATIONPARAM_H

#include "decomp.h"
#include "mxnotificationparam.h"

// VTABLE: LEGO1 0x100d7e80
// SIZE 0x10
class MxType18NotificationParam : public MxNotificationParam {
public:
	MxType18NotificationParam(NotificationId p_type, MxCore* p_sender, undefined4 p_unk0x0c)
		: MxNotificationParam(p_type, p_sender), m_unk0x0c(p_unk0x0c)
	{
	}

	// FUNCTION: LEGO1 0x1004afd0
	MxNotificationParam* Clone() const override
	{
		return new MxType18NotificationParam(m_type, m_sender, m_unk0x0c);
	} // vtable+0x04

protected:
	undefined4 m_unk0x0c; // 0x0c
};

// SYNTHETIC: LEGO1 0x1004b080
// MxType18NotificationParam::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1004b0f0
// MxType18NotificationParam::~MxType18NotificationParam

#endif // MXTYPE18NOTIFICATIONPARAM_H
