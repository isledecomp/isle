#ifndef MXTYPE19NOTIFICATIONPARAM_H
#define MXTYPE19NOTIFICATIONPARAM_H

#include "decomp.h"
#include "mxnotificationparam.h"

// VTABLE: LEGO1 0x100d6230
// SIZE 0x10
class MxType19NotificationParam : public MxNotificationParam {
public:
	MxType19NotificationParam(NotificationId p_type, MxCore* p_sender, MxU8 p_unk0x0e, MxU16 p_unk0x0c)
		: MxNotificationParam()
	{
		m_type = p_type;
		m_sender = p_sender;
		m_unk0x0c = p_unk0x0c;
		m_unk0x0e = p_unk0x0e;
	}

	// FUNCTION: LEGO1 0x1001bac0
	MxNotificationParam* Clone() const override
	{
		return new MxType19NotificationParam(m_type, m_sender, m_unk0x0e, m_unk0x0c);
	} // vtable+0x04

protected:
	MxU16 m_unk0x0c; // 0x0c
	MxU8 m_unk0x0e;  // 0x0e
};

// SYNTHETIC: LEGO1 0x1001bb80
// MxType19NotificationParam::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1001bbf0
// MxType19NotificationParam::~MxType19NotificationParam

#endif // MXTYPE19NOTIFICATIONPARAM_H
