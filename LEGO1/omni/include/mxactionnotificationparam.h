#ifndef MXACTIONNOTIFICATIONPARAM_H
#define MXACTIONNOTIFICATIONPARAM_H

#include "mxdsaction.h"
#include "mxnotificationparam.h"

class MxPresenter;

// VTABLE: LEGO1 0x100d8350
// SIZE 0x14
class MxActionNotificationParam : public MxNotificationParam {
public:
	MxActionNotificationParam(NotificationId p_type, MxCore* p_sender, MxDSAction* p_action, MxBool p_reallocAction)
		: MxNotificationParam(p_type, p_sender)
	{
		MxDSAction* oldAction = p_action;
		m_realloc = p_reallocAction;

		if (p_reallocAction) {
			m_action = new MxDSAction();
		}
		else {
			m_action = oldAction;
			return;
		}

		m_action->SetAtomId(oldAction->GetAtomId());
		m_action->SetObjectId(oldAction->GetObjectId());
		m_action->SetFlags(oldAction->GetFlags());
	}

	// FUNCTION: LEGO1 0x10051050
	~MxActionNotificationParam() override
	{
		if (!m_realloc) {
			return;
		}

		if (m_action) {
			delete m_action;
		}
	}

	// FUNCTION: LEGO1 0x100510c0
	MxNotificationParam* Clone() const override
	{
		return new MxActionNotificationParam(m_type, m_sender, m_action, m_realloc);
	} // vtable+0x04

	// FUNCTION: BETA10 0x10017970
	MxDSAction* GetAction() { return m_action; }

protected:
	MxDSAction* m_action; // 0x0c
	MxBool m_realloc;     // 0x10
};

// VTABLE: LEGO1 0x100dc210
// SIZE 0x14
class MxStartActionNotificationParam : public MxActionNotificationParam {
public:
	MxStartActionNotificationParam(
		NotificationId p_type,
		MxCore* p_sender,
		MxDSAction* p_action,
		MxBool p_reallocAction
	)
		: MxActionNotificationParam(p_type, p_sender, p_action, p_reallocAction)
	{
	}

	MxNotificationParam* Clone() const override; // vtable+0x04
};

// VTABLE: LEGO1 0x100d8358
// SIZE 0x14
class MxEndActionNotificationParam : public MxActionNotificationParam {
public:
	MxEndActionNotificationParam(NotificationId p_type, MxCore* p_sender, MxDSAction* p_action, MxBool p_reallocAction)
		: MxActionNotificationParam(p_type, p_sender, p_action, p_reallocAction)
	{
	}

	// FUNCTION: LEGO1 0x10051270
	MxNotificationParam* Clone() const override
	{
		return new MxEndActionNotificationParam(c_notificationEndAction, m_sender, m_action, m_realloc);
	} // vtable+0x04
};

// VTABLE: LEGO1 0x100dc208
// SIZE 0x18
class MxType4NotificationParam : public MxActionNotificationParam {
public:
	MxType4NotificationParam(MxCore* p_sender, MxDSAction* p_action, MxPresenter* p_unk0x14)
		: MxActionNotificationParam(c_notificationType4, p_sender, p_action, FALSE)
	{
		m_unk0x14 = p_unk0x14;
	}

	MxNotificationParam* Clone() const override; // vtable+0x04

private:
	MxPresenter* m_unk0x14; // 0x14
};

// SYNTHETIC: LEGO1 0x100511e0
// MxActionNotificationParam::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100513a0
// MxEndActionNotificationParam::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x10051410
// MxEndActionNotificationParam::~MxEndActionNotificationParam

// SYNTHETIC: LEGO1 0x100b0430
// MxStartActionNotificationParam::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100b04a0
// MxStartActionNotificationParam::~MxStartActionNotificationParam

// SYNTHETIC: LEGO1 0x100b05c0
// MxType4NotificationParam::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100b0630
// MxType4NotificationParam::~MxType4NotificationParam

#endif
