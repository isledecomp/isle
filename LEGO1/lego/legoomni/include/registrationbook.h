#ifndef REGISTRATIONBOOK_H
#define REGISTRATIONBOOK_H

#include "jukebox.h"
#include "legoworld.h"
#include "mxcontrolpresenter.h"
#include "mxstillpresenter.h"

class InfocenterState;
class MxEndActionNotificationParam;
class LegoControlManagerEvent;

// VTABLE: LEGO1 0x100d9928
// SIZE 0x2d0
class RegistrationBook : public LegoWorld {
public:
	RegistrationBook();
	~RegistrationBook() override; // vtable+0x00

	MxLong Notify(MxParam& p_param) override; // vtable+0x04
	MxResult Tickle() override;               // vtable+0x08

	// FUNCTION: LEGO1 0x10076e10
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f04c8
		return "RegistrationBook";
	}

	// FUNCTION: LEGO1 0x10076e20
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, RegistrationBook::ClassName()) || LegoWorld::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override; // vtable+0x18
	void ReadyWorld() override;                       // vtable+0x50
	MxBool VTable0x64() override;                     // vtable+0x64
	void Enable(MxBool p_enable) override;            // vtable+0x68

	inline void PlayAction(MxU32 p_objectId);

	// SYNTHETIC: LEGO1 0x10076f30
	// RegistrationBook::`scalar deleting destructor'

private:
	undefined4 m_unk0xf8;             // 0xf8
	undefined m_unk0xfc;              // 0xfc
	undefined m_unk0xfd[3];           // 0xfd
	MxStillPresenter* m_alphabet[26]; // 0x100
	MxStillPresenter* m_name[10][7];  // 0x168
	struct {
		undefined4 m_unk0x00[3];         // 0x00
		undefined2 m_unk0x0c;            // 0x0c
		undefined2 m_unk0x0e;            // 0x0e
	} m_unk0x280;                        // 0x280
	MxControlPresenter* m_checkmark[10]; // 0x290
	undefined2 m_unk0x2b8;               // 0x2b8
	InfocenterState* m_infocenterState;  // 0x2bc
	undefined m_unk0x2c0;                // 0x2c0
	undefined m_unk0x2c1;                // 0x2c1
	undefined m_unk0x2c2[0x02];          // 0x2c2
	undefined4 m_unk0x2c4;               // 0x2c4
	undefined4 m_unk0x2c8;               // 0x2c8
	undefined4 m_unk0x2cc;               // 0x2cc

	MxLong HandleEndAction(MxEndActionNotificationParam& p_param);
	MxLong HandleKeyPress(MxS8 p_key);
	MxLong HandleClick(LegoControlManagerEvent& p_param);
	MxLong HandleNotification19(MxParam& p_param);
	void FUN_100775c0(MxS16 p_playerIndex);
};

#endif // REGISTRATIONBOOK_H
