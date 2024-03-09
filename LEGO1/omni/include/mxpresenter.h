#ifndef MXPRESENTER_H
#define MXPRESENTER_H

#include "decomp.h"
#include "mxcore.h"
#include "mxcriticalsection.h"
#include "mxdsaction.h"
#include "mxpoint32.h"

class MxCompositePresenter;
class MxStreamController;
class MxEntity;

// VTABLE: LEGO1 0x100d4d38
// SIZE 0x40
class MxPresenter : public MxCore {
public:
	enum TickleState {
		e_idle = 0,
		e_ready,
		e_starting,
		e_streaming,
		e_repeating,
		e_unk5,
		e_done,
	};

	MxPresenter() { Init(); }

	// FUNCTION: LEGO1 0x1000bf00
	~MxPresenter() override {} // vtable+0x00

	MxResult Tickle() override; // vtable+0x08

	// FUNCTION: LEGO1 0x1000bfe0
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0740
		return "MxPresenter";
	}

	// FUNCTION: LEGO1 0x1000bff0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxPresenter::ClassName()) || MxCore::IsA(p_name);
	}

	// FUNCTION: LEGO1 0x1000be30
	virtual void VTable0x14() {} // vtable+0x14

	// FUNCTION: LEGO1 0x1000be40
	virtual void ReadyTickle()
	{
		ParseExtra();
		ProgressTickleState(e_starting);
	} // vtable+0x18

	// FUNCTION: LEGO1 0x1000be60
	virtual void StartingTickle() { ProgressTickleState(e_streaming); } // vtable+0x1c

	// FUNCTION: LEGO1 0x1000be80
	virtual void StreamingTickle() { ProgressTickleState(e_repeating); } // vtable+0x20

	// FUNCTION: LEGO1 0x1000bea0
	virtual void RepeatingTickle() { ProgressTickleState(e_unk5); } // vtable+0x24

	// FUNCTION: LEGO1 0x1000bec0
	virtual void Unk5Tickle() { ProgressTickleState(e_done); } // vtable+0x28

protected:
	// FUNCTION: LEGO1 0x1000bee0
	virtual void DoneTickle() { ProgressTickleState(e_idle); } // vtable+0x2c

	virtual void ParseExtra(); // vtable+0x30

	inline void ProgressTickleState(TickleState p_tickleState)
	{
		m_previousTickleStates |= 1 << (MxU8) m_currentTickleState;
		m_currentTickleState = p_tickleState;
	}

public:
	// FUNCTION: LEGO1 0x1000bf70
	virtual MxResult AddToManager() { return SUCCESS; } // vtable+0x34

	// FUNCTION: LEGO1 0x1000bf80
	virtual void Destroy() { Init(); } // vtable+0x38

	virtual MxResult StartAction(MxStreamController*, MxDSAction*); // vtable+0x3c
	virtual void EndAction();                                       // vtable+0x40

	// FUNCTION: LEGO1 0x1000bf90
	virtual void SetTickleState(TickleState p_tickleState) { ProgressTickleState(p_tickleState); } // vtable+0x44

	// FUNCTION: LEGO1 0x1000bfb0
	virtual MxBool HasTickleStatePassed(TickleState p_tickleState)
	{
		return m_previousTickleStates & (1 << (MxU8) p_tickleState);
	} // vtable+0x48

	// FUNCTION: LEGO1 0x1000bfc0
	virtual MxResult PutData() { return SUCCESS; } // vtable+0x4c

	// FUNCTION: LEGO1 0x1000bfd0
	virtual MxBool IsHit(MxS32 p_x, MxS32 p_y) { return FALSE; } // vtable+0x50

	virtual void Enable(MxBool p_enable); // vtable+0x54

	MxEntity* CreateEntity(const char* p_defaultName);
	void SendToCompositePresenter(MxOmni*);
	MxBool IsEnabled();

	inline MxS32 GetCurrentTickleState() const { return this->m_currentTickleState; }
	inline MxPoint32 GetLocation() const { return this->m_location; }
	inline MxS32 GetX() const { return this->m_location.GetX(); }
	inline MxS32 GetY() const { return this->m_location.GetY(); }
	inline MxS32 GetDisplayZ() const { return this->m_displayZ; }
	inline MxDSAction* GetAction() const { return this->m_action; }
	inline void SetAction(MxDSAction* p_action) { m_action = p_action; }

	inline void SetCompositePresenter(MxCompositePresenter* p_compositePresenter)
	{
		m_compositePresenter = p_compositePresenter;
	}

	inline void SetDisplayZ(MxS32 p_displayZ) { m_displayZ = p_displayZ; }

	// SYNTHETIC: LEGO1 0x1000c070
	// MxPresenter::`scalar deleting destructor'

protected:
	void Init();

	TickleState m_currentTickleState;           // 0x08
	MxU32 m_previousTickleStates;               // 0x0c
	MxPoint32 m_location;                       // 0x10
	MxS32 m_displayZ;                           // 0x18
	MxDSAction* m_action;                       // 0x1c
	MxCriticalSection m_criticalSection;        // 0x20
	MxCompositePresenter* m_compositePresenter; // 0x3c
};

const char* PresenterNameDispatch(const MxDSAction&);

#endif // MXPRESENTER_H
