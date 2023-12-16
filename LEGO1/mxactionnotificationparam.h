#ifndef MXACTIONNOTIFICATIONPARAM_H
#define MXACTIONNOTIFICATIONPARAM_H

#include "mxdsaction.h"
#include "mxnotificationparam.h"

class MxPresenter;

// VTABLE: LEGO1 0x100d8350
// SIZE 0x14
class MxActionNotificationParam : public MxNotificationParam {
public:
	inline MxActionNotificationParam(
		NotificationId p_type,
		MxCore* p_sender,
		MxDSAction* p_action,
		MxBool p_reallocAction
	)
		: MxNotificationParam(p_type, p_sender)
	{
		MxDSAction* oldAction = p_action;
		this->m_realloc = p_reallocAction;

		if (p_reallocAction)
			this->m_action = new MxDSAction();
		else {
			this->m_action = oldAction;
			return;
		}

		this->m_action->SetAtomId(oldAction->GetAtomId());
		this->m_action->SetObjectId(oldAction->GetObjectId());
		this->m_action->SetUnknown24(oldAction->GetUnknown24());
	}

	// FUNCTION: LEGO1 0x10051050
	inline virtual ~MxActionNotificationParam() override
	{
		if (!this->m_realloc)
			return;

		if (this->m_action)
			delete this->m_action;
	}

	virtual MxNotificationParam* Clone() override; // vtable+0x4

	inline MxDSAction* GetAction() { return m_action; }

protected:
	MxDSAction* m_action; // 0xc
	MxBool m_realloc;     // 0x10
};

// VTABLE: LEGO1 0x100dc210
// SIZE 0x14
class MxStartActionNotificationParam : public MxActionNotificationParam {
public:
	inline MxStartActionNotificationParam(
		NotificationId p_type,
		MxCore* p_sender,
		MxDSAction* p_action,
		MxBool p_reallocAction
	)
		: MxActionNotificationParam(p_type, p_sender, p_action, p_reallocAction)
	{
	}

	virtual MxNotificationParam* Clone() override; // vtable+0x4
};

// VTABLE: LEGO1 0x100d8358
// SIZE 0x14
class MxEndActionNotificationParam : public MxActionNotificationParam {
public:
	inline MxEndActionNotificationParam(
		NotificationId p_type,
		MxCore* p_sender,
		MxDSAction* p_action,
		MxBool p_reallocAction
	)
		: MxActionNotificationParam(p_type, p_sender, p_action, p_reallocAction)
	{
	}

	virtual MxNotificationParam* Clone() override; // vtable+0x4
};

// VTABLE: LEGO1 0x100dc208
// SIZE 0x18
class MxType4NotificationParam : public MxActionNotificationParam {
public:
	inline MxType4NotificationParam(MxCore* p_sender, MxDSAction* p_action, MxPresenter* p_unk0x14)
		: MxActionNotificationParam(TYPE4, p_sender, p_action, FALSE)
	{
		m_unk0x14 = p_unk0x14;
	}

	virtual MxNotificationParam* Clone() override; // vtable+0x4

private:
	MxPresenter* m_unk0x14; // 0x14
};

// SYNTHETIC: LEGO1 0x100513a0
// MxEndActionNotificationParam::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100b0430
// MxStartActionNotificationParam::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100b05c0
// MxType4NotificationParam::`scalar deleting destructor'

#endif
