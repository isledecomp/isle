#ifndef MXDSMULTIACTION_H
#define MXDSMULTIACTION_H

#include "mxdsaction.h"
#include "mxdsactionlist.h"

// VTABLE: LEGO1 0x100dcef0
// SIZE 0x9c
class MxDSMultiAction : public MxDSAction {
public:
	MxDSMultiAction();
	virtual ~MxDSMultiAction() override;

	void CopyFrom(MxDSMultiAction& p_dsMultiAction);
	MxDSMultiAction& operator=(MxDSMultiAction& p_dsMultiAction);

	// FUNCTION: LEGO1 0x100c9f50
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x10101dbc
		return "MxDSMultiAction";
	}

	// FUNCTION: LEGO1 0x100c9f60
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxDSMultiAction::ClassName()) || MxDSAction::IsA(p_name);
	}

	virtual undefined4 VTable0x14() override;                            // vtable+14;
	virtual MxU32 GetSizeOnDisk() override;                              // vtable+18;
	virtual void Deserialize(MxU8** p_source, MxS16 p_unk0x24) override; // vtable+1c;
	virtual void SetAtomId(MxAtomId p_atomId) override;                  // vtable+20;
	virtual MxDSAction* Clone() override;                                // vtable+2c;
	virtual void MergeFrom(MxDSAction& p_dsAction) override;             // vtable+30;
	virtual MxBool HasId(MxU32 p_objectId) override;                     // vtable+34;
	virtual void SetUnknown90(MxLong p_unk0x90) override;                // vtable+38;

	inline MxDSActionList* GetActionList() const { return m_actions; };

protected:
	MxU32 m_sizeOnDisk;        // 0x94
	MxDSActionList* m_actions; // 0x98
};

// SYNTHETIC: LEGO1 0x1004ad10
// MxDSActionListCursor::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x1004ad80
// MxListCursor<MxDSAction *>::~MxListCursor<MxDSAction *>

// SYNTHETIC: LEGO1 0x1004add0
// MxListCursor<MxDSAction *>::`scalar deleting destructor'

// FUNCTION: LEGO1 0x1004ae40
// MxDSActionListCursor::~MxDSActionListCursor

#endif // MXDSMULTIACTION_H
