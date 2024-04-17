#include "mxvariabletable.h"

// FUNCTION: LEGO1 0x100b7330
// FUNCTION: BETA10 0x1012a470
MxS8 MxVariableTable::Compare(MxVariable* p_var0, MxVariable* p_var1)
{
	return p_var0->GetKey()->Compare(*p_var1->GetKey());
}

// FUNCTION: LEGO1 0x100b7370
// FUNCTION: BETA10 0x1012a4a0
MxU32 MxVariableTable::Hash(MxVariable* p_var)
{
	const char* str = p_var->GetKey()->GetData();
	MxU32 value = 0;

	for (MxS32 i = 0; str[i]; i++) {
		value += str[i];
	}

	return value;
}

// FUNCTION: LEGO1 0x100b73a0
// FUNCTION: BETA10 0x1012a507
void MxVariableTable::SetVariable(const char* p_key, const char* p_value)
{
	MxHashTableCursor<MxVariable*> cursor(this);
	MxVariable* var = new MxVariable(p_key, p_value);

	if (cursor.Find(var)) {
		delete var;
		cursor.Current(var);
		var->SetValue(p_value);
	}
	else {
		MxHashTable<MxVariable*>::Add(var);
	}
}

// FUNCTION: LEGO1 0x100b7740
// FUNCTION: BETA10 0x1012a629
void MxVariableTable::SetVariable(MxVariable* p_var)
{
	MxHashTableCursor<MxVariable*> cursor(this);

	if (cursor.Find(p_var)) {
		cursor.DeleteMatch();
	}

	MxHashTable<MxVariable*>::Add(p_var);
}

// FUNCTION: LEGO1 0x100b78f0
// FUNCTION: BETA10 0x1012a6bd
const char* MxVariableTable::GetVariable(const char* p_key)
{
	// STRING: ISLE 0x41008c
	// STRING: LEGO1 0x100f01d4
	const char* value = "";
	MxHashTableCursor<MxVariable*> cursor(this);
	MxVariable* var = new MxVariable(p_key);

	MxBool found = cursor.Find(var);
	delete var;

	if (found) {
		cursor.Current(var);
		value = var->GetValue()->GetData();
	}

	return value;
}
