#include "mxvariabletable.h"

// OFFSET: LEGO1 0x100b7370
int MxVariableTable::KeyChecksum(MxVariable *p_var)
{
  const char *str = p_var->GetKey()->GetData();
  int value = 0;
  
  for (int i = 0; str[i]; i++) {
    value += (int)str[i];
  }

  return value;
}

// OFFSET: LEGO1 0x100b73a0
void MxVariableTable::SetVariable(const char *p_key, const char *p_value)
{
  MxVariable *var = new MxVariable();
  // TODO
}

// OFFSET: LEGO1 0x100b7740
void MxVariableTable::SetVariable(MxVariable *var)
{
  // TODO
}

// OFFSET: LEGO1 0x100b78f0
const char *MxVariableTable::GetVariable(const char *key)
{
  // TODO
  return 0;
}
