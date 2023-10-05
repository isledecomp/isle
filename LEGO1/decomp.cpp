#include "decomp.h"

#include "Windows.h"

// Export "Patch" function (non-mangled name)
extern "C" __declspec(dllexport) void Patch(void *root)
{
  MessageBoxA(NULL, "HELLO", "HELLO", 0);
}
