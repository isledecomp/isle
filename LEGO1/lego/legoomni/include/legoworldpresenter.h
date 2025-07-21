#ifndef LEGOWORLDPRESENTER_H
#define LEGOWORLDPRESENTER_H

#include "legoentitypresenter.h"

#include <stdio.h>

class LegoWorld;
struct ModelDbPart;
struct ModelDbModel;

// VTABLE: LEGO1 0x100d8ee0
// SIZE 0x54
class LegoWorldPresenter : public LegoEntityPresenter {
public:
	LegoWorldPresenter();
	~LegoWorldPresenter() override; // vtable+0x00

	static void configureLegoWorldPresenter(MxS32 p_legoWorldPresenterQuality);

	// FUNCTION: BETA10 0x100e41c0
	static const char* HandlerClassName()
	{
		// STRING: LEGO1 0x100f0608
		return "LegoWorldPresenter";
	}

	// FUNCTION: LEGO1 0x10066630
	// FUNCTION: BETA10 0x100e4190
	const char* ClassName() const override // vtable+0x0c
	{
		return HandlerClassName();
	}

	// FUNCTION: LEGO1 0x10066640
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoWorldPresenter::ClassName()) || LegoEntityPresenter::IsA(p_name);
	}

	void ReadyTickle() override;                                                           // vtable+0x18
	void StartingTickle() override;                                                        // vtable+0x1c
	void ParseExtra() override;                                                            // vtable+0x30
	MxResult StartAction(MxStreamController* p_controller, MxDSAction* p_action) override; // vtable+0x3c
	void AdvanceSerialAction(MxPresenter* p_presenter) override;                           // vtable+0x60

	MxResult LoadWorld(char* p_worldName, LegoWorld* p_world);

	// SYNTHETIC: LEGO1 0x10066750
	// LegoWorldPresenter::`scalar deleting destructor'

private:
	MxResult LoadWorldPart(ModelDbPart& p_part, FILE* p_wdbFile);
	MxResult LoadWorldModel(ModelDbModel& p_model, FILE* p_wdbFile, LegoWorld* p_world);

	MxU32 m_nextObjectId;
};

#endif // LEGOWORLDPRESENTER_H
