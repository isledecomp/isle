#ifndef MXVARIABLETABLE_H
#define MXVARIABLETABLE_H

class MxVariable;

// VTABLE 0x100dc1c8
// SIZE 0x28
class MxVariableTable
{
public:
  __declspec(dllexport) const char * GetVariable(const char *key);
  __declspec(dllexport) void SetVariable(MxVariable *var);
  __declspec(dllexport) void SetVariable(const char *key, const char *value);
};

#endif // MXVARIABLETABLE_H
