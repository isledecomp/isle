#ifndef MXNOTIFICATIONPARAM_H
#define MXNOTIFICATIONPARAM_H

#include "compat.h"
#include "mxparam.h"
#include "mxtypes.h"

class MxCore;

enum NotificationId {
	c_notificationType0 = 0,
	c_notificationStartAction = 1, // 100dc210:100d8350
	c_notificationEndAction = 2,   // 100d8358:100d8350
	c_notificationType4 = 4,       // 100dc208:100d8350
	c_notificationPresenter = 5,
	c_notificationStreamer = 6,   // 100dc760
	c_notificationKeyPress = 7,   // 100d6aa0
	c_notificationButtonUp = 8,   // 100d6aa0
	c_notificationButtonDown = 9, // 100d6aa0
	c_notificationMouseMove = 10, // 100d6aa0
	c_notificationType11 = 11,    // 100d6aa0
	c_notificationDragEnd = 12,
	c_notificationDragStart = 13,
	c_notificationDrag = 14,
	c_notificationTimer = 15, // 100d6aa0
	c_notificationClick = 17,
	c_notificationType18 = 18, // 100d7e80
	c_notificationType19 = 19, // 100d6230
	c_notificationType20 = 20,
	c_notificationNewPresenter = 21,
	c_notificationType22 = 22,
	c_notificationType23 = 23,
	c_notificationTransitioned = 24
};

// VTABLE: LEGO1 0x100d56e0
// SIZE 0x0c
class MxNotificationParam : public MxParam {
public:
	inline MxNotificationParam(NotificationId p_type, MxCore* p_sender) : MxParam(), m_type(p_type), m_sender(p_sender)
	{
	}

	// FUNCTION: LEGO1 0x10010390
	virtual MxNotificationParam* Clone() { return new MxNotificationParam(m_type, m_sender); } // vtable+0x04

	inline NotificationId GetNotification() const { return m_type; }
	inline MxCore* GetSender() const { return m_sender; }
	inline NotificationId GetType() const { return m_type; }

	inline void SetType(NotificationId p_type) { m_type = p_type; }
	inline void SetSender(MxCore* p_sender) { m_sender = p_sender; }

protected:
	NotificationId m_type; // 0x04
	MxCore* m_sender;      // 0x08
};

// SYNTHETIC: LEGO1 0x10010430
// MxNotificationParam::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100104a0
// MxNotificationParam::~MxNotificationParam

#endif // MXNOTIFICATIONPARAM_H
