#ifndef MXVARIABLETABLE_H
#define MXVARIABLETABLE_H

#include "mxhashtable.h"
#include "mxtypes.h"
#include "mxvariable.h"

// VTABLE: LEGO1 0x100dc1c8
// VTABLE: BETA10 0x101c1c78
// SIZE 0x28
class MxVariableTable : public MxHashTable<MxVariable*> {
public:
	// FUNCTION: BETA10 0x10130e50
	MxVariableTable() { SetDestroy(Destroy); }
	void SetVariable(const char* p_key, const char* p_value);
	void SetVariable(MxVariable* p_var);
	const char* GetVariable(const char* p_key);

	// FUNCTION: LEGO1 0x100afdb0
	// FUNCTION: BETA10 0x10130f00
	static void Destroy(MxVariable* p_obj) { p_obj->Destroy(); }

	MxS8 Compare(MxVariable*, MxVariable*) override; // vtable+0x14
	MxU32 Hash(MxVariable*) override;                // vtable+0x18

	// SYNTHETIC: LEGO1 0x100afdd0
	// SYNTHETIC: BETA10 0x10130f20
	// MxVariableTable::`scalar deleting destructor'
};

// VTABLE: LEGO1 0x100dc1b0
// VTABLE: BETA10 0x101c1cd0
// class MxCollection<MxVariable *>

// VTABLE: LEGO1 0x100dc1e8
// VTABLE: BETA10 0x101c1cb0
// class MxHashTable<MxVariable *>

// VTABLE: LEGO1 0x100dc680
// VTABLE: BETA10 0x101c1b48
// class MxHashTableCursor<MxVariable *>

// TEMPLATE: LEGO1 0x100afcd0
// TEMPLATE: BETA10 0x10132950
// MxCollection<MxVariable *>::Compare

// TEMPLATE: LEGO1 0x100afce0
// TEMPLATE: BETA10 0x10132a00
// MxCollection<MxVariable *>::~MxCollection<MxVariable *>

// TEMPLATE: LEGO1 0x100afd30
// TEMPLATE: BETA10 0x10132a70
// MxCollection<MxVariable *>::Destroy

// SYNTHETIC: LEGO1 0x100afd40
// SYNTHETIC: BETA10 0x10132a80
// MxCollection<MxVariable *>::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x100afdc0
// TEMPLATE: BETA10 0x10132ac0
// MxHashTable<MxVariable *>::Hash

// TEMPLATE: LEGO1 0x100b0bd0
// TEMPLATE: BETA10 0x10132ae0
// MxHashTable<MxVariable *>::~MxHashTable<MxVariable *>

// SYNTHETIC: LEGO1 0x100b0ca0
// SYNTHETIC: BETA10 0x10132b70
// MxHashTable<MxVariable *>::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x100b7680
// TEMPLATE: BETA10 0x1012a990
// MxHashTableCursor<MxVariable *>::~MxHashTableCursor<MxVariable *>

// SYNTHETIC: LEGO1 0x100b76d0
// SYNTHETIC: BETA10 0x1012a9f0
// MxHashTableCursor<MxVariable *>::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x100b7ab0
// TEMPLATE: BETA10 0x1012adc0
// MxHashTable<MxVariable *>::Resize

// TEMPLATE: LEGO1 0x100b7b80
// TEMPLATE: BETA10 0x1012af10
// MxHashTable<MxVariable *>::NodeInsert

// TEMPLATE: BETA10 0x1012a900
// MxHashTableCursor<MxVariable *>::MxHashTableCursor<MxVariable *>

// TEMPLATE: BETA10 0x1012aae0
// MxHashTable<MxVariable *>::Add

// TEMPLATE: BETA10 0x1012abd0
// MxHashTableCursor<MxVariable *>::Current

// TEMPLATE: BETA10 0x1012ac20
// MxHashTableCursor<MxVariable *>::DeleteMatch

// TEMPLATE: BETA10 0x1012ad00
// MxHashTableCursor<MxVariable *>::Find

// TEMPLATE: BETA10 0x1012af90
// MxHashTableNode<MxVariable *>::MxHashTableNode<MxVariable *>

// TEMPLATE: BETA10 0x10132890
// MxHashTable<MxVariable *>::MxHashTable<MxVariable *>

// TEMPLATE: BETA10 0x10130ed0
// MxCollection<MxVariable *>::SetDestroy

// SYNTHETIC: BETA10 0x10130f60
// MxVariableTable::~MxVariableTable

// SYNTHETIC: BETA10 0x10132970
// MxCollection<MxVariable *>::MxCollection<MxVariable *>

// TEMPLATE: BETA10 0x10132bb0
// MxHashTable<MxVariable *>::DeleteAll

#endif // MXVARIABLETABLE_H
