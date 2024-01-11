#ifndef MXNOTIFICATIONPARAM_H
#define MXNOTIFICATIONPARAM_H

#include "compat.h"
#include "mxparam.h"
#include "mxtypes.h"

class MxCore;

enum NotificationId {
	PARAM_NONE = 0,
	c_notificationStartAction = 1, // 100dc210:100d8350
	c_notificationEndAction = 2,   // 100d8358:100d8350
	TYPE4 = 4,                     // 100dc208:100d8350
	MXPRESENTER_NOTIFICATION = 5,
	MXSTREAMER_DELETE_NOTIFY = 6, // 100dc760
	c_notificationKeyPress = 7,   // 100d6aa0
	c_notificationButtonUp = 8,   // 100d6aa0
	c_notificationButtonDown = 9, // 100d6aa0
	c_notificationMouseMove = 10, // 100d6aa0
	TYPE11 = 11,                  // 100d6aa0
	c_notificationDragEnd = 12,
	c_notificationDragStart = 13,
	c_notificationDrag = 14,
	c_notificationTimer = 15, // 100d6aa0
	TYPE17 = 17,
	TYPE18 = 18, // 100d7e80
	TYPE19 = 19, // 100d6230
	TYPE20 = 20,
	c_notificationNewPresenter = 21,
	TYPE22 = 22,
	TYPE23 = 23,
	MXTRANSITIONMANAGER_TRANSITIONENDED = 24
};

// VTABLE: LEGO1 0x100d56e0
class MxNotificationParam : public MxParam {
public:
	inline MxNotificationParam(NotificationId p_type, MxCore* p_sender) : MxParam(), m_type(p_type), m_sender(p_sender)
	{
	}

	virtual ~MxNotificationParam() override {}

	// FUNCTION: LEGO1 0x10010390
	virtual MxNotificationParam* Clone() { return new MxNotificationParam(m_type, m_sender); }; // vtable+0x4

	inline NotificationId GetNotification() const { return m_type; }
	inline MxCore* GetSender() const { return m_sender; }
	inline NotificationId GetType() const { return m_type; }

protected:
	NotificationId m_type; // 0x4
	MxCore* m_sender;      // 0x8
};

#endif // MXNOTIFICATIONPARAM_H
