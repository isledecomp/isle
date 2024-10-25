#ifndef MXNOTIFICATIONPARAM_H
#define MXNOTIFICATIONPARAM_H

#include "compat.h"
#include "mxparam.h"
#include "mxtypes.h"

class MxCore;

// Several of those should be defined in LegoOmni
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
	c_notificationClick = 11,     // 100d6aa0
	c_notificationDragEnd = 12,
	c_notificationDragStart = 13,
	c_notificationDrag = 14,
	c_notificationTimer = 15, // 100d6aa0
	c_notificationControl = 17,
	c_notificationEndAnim = 18,    // 100d7e80
	c_notificationPathStruct = 19, // 100d6230
	c_notificationType20 = 20,
	c_notificationNewPresenter = 21,
	c_notificationType22 = 22,
	c_notificationType23 = 23,
	c_notificationTransitioned = 24
};

// VTABLE: LEGO1 0x100d56e0
// VTABLE: BETA10 0x101b86a8
// SIZE 0x0c
class MxNotificationParam : public MxParam {
public:
	// FUNCTION: BETA10 0x100702d0
	MxNotificationParam() : m_type(c_notificationType0), m_sender(NULL) {}

	// FUNCTION: BETA10 0x10013490
	MxNotificationParam(NotificationId p_type, MxCore* p_sender) : MxParam(), m_type(p_type), m_sender(p_sender) {}

	// FUNCTION: LEGO1 0x10010390
	// FUNCTION: BETA10 0x100135f0
	virtual MxNotificationParam* Clone() const { return new MxNotificationParam(m_type, m_sender); } // vtable+0x04

	// FUNCTION: BETA10 0x100135c0
	NotificationId GetNotification() const { return m_type; }

	// FUNCTION: BETA10 0x1003c960
	MxCore* GetSender() const { return m_sender; }

	void SetNotification(NotificationId p_type) { m_type = p_type; }
	void SetSender(MxCore* p_sender) { m_sender = p_sender; }

protected:
	NotificationId m_type; // 0x04
	MxCore* m_sender;      // 0x08
};

// SYNTHETIC: LEGO1 0x10010430
// SYNTHETIC: BETA10 0x100136c0
// MxNotificationParam::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100104a0
// SYNTHETIC: BETA10 0x10013740
// MxNotificationParam::~MxNotificationParam

#endif // MXNOTIFICATIONPARAM_H
