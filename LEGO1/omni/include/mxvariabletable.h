#ifndef MXVARIABLETABLE_H
#define MXVARIABLETABLE_H

#include "mxhashtable.h"
#include "mxtypes.h"
#include "mxvariable.h"

// VTABLE: LEGO1 0x100dc1c8
// SIZE 0x28
class MxVariableTable : public MxHashTable<MxVariable*> {
public:
	MxVariableTable() { m_customDestructor = Destroy; }
	void SetVariable(const char* p_key, const char* p_value);
	void SetVariable(MxVariable* p_var);
	const char* GetVariable(const char* p_key);

	static void Destroy(MxVariable* p_obj) { p_obj->Destroy(); }

	MxS8 Compare(MxVariable*, MxVariable*) override; // vtable+0x14
	MxU32 Hash(MxVariable*) override;                // vtable+0x18

	// SYNTHETIC: LEGO1 0x100afdd0
	// MxVariableTable::`scalar deleting destructor'
};

// VTABLE: LEGO1 0x100dc1b0
// class MxCollection<MxVariable *>

// VTABLE: LEGO1 0x100dc1e8
// class MxHashTable<MxVariable *>

// VTABLE: LEGO1 0x100dc680
// class MxHashTableCursor<MxVariable *>

// TEMPLATE: LEGO1 0x100afcd0
// MxCollection<MxVariable *>::Compare

// TEMPLATE: LEGO1 0x100afce0
// MxCollection<MxVariable *>::~MxCollection<MxVariable *>

// TEMPLATE: LEGO1 0x100afd30
// MxCollection<MxVariable *>::Destroy

// SYNTHETIC: LEGO1 0x100afd40
// MxCollection<MxVariable *>::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x100afdb0
// MxVariableTable::Destroy

// TEMPLATE: LEGO1 0x100afdc0
// MxHashTable<MxVariable *>::Hash

// TEMPLATE: LEGO1 0x100b0bd0
// MxHashTable<MxVariable *>::~MxHashTable<MxVariable *>

// SYNTHETIC: LEGO1 0x100b0ca0
// MxHashTable<MxVariable *>::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x100b7680
// MxHashTableCursor<MxVariable *>::~MxHashTableCursor<MxVariable *>

// SYNTHETIC: LEGO1 0x100b76d0
// MxHashTableCursor<MxVariable *>::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x100b7ab0
// MxHashTable<MxVariable *>::Resize

// TEMPLATE: LEGO1 0x100b7b80
// MxHashTable<MxVariable *>::NodeInsert

#endif // MXVARIABLETABLE_H
