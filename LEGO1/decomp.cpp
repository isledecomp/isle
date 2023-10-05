#include "decomp.h"

#include "Windows.h"

#include <stdio.h>

#ifdef ISLE_BUILD_PATCH

// Managed list class for patches
static class DecompPatchList
{
private:
  struct DecompPatchNode
  {
    DecompPatchNode *next;
    void *origFunc, *newFunc;
  } *m_head;

public:
  DecompPatchList()
  {
    // I'm having CRT initialization order issues
    // with MSVC 4.20, so I'm going to leave m_head
    // uninitialized. It's static so it should be
    // zeroed anyways.
    // m_head = NULL;
  }

  ~DecompPatchList()
  {
    // Delete all nodes
    for (DecompPatchNode *node = m_head; node != NULL;)
    {
      DecompPatchNode *next = node->next;
      delete node;
      node = next;
    }
  }

  void Add(void *origFunc, void *newFunc)
  {
    // Create new node
    DecompPatchNode *node = new DecompPatchNode;
    node->origFunc = origFunc;
    node->newFunc = newFunc;
    node->next = m_head;

    // Add to head of list
    m_head = node;
  }

  void Patch(void *root)
  {
    // Go through all nodes
    for (DecompPatchNode *node = m_head; node != NULL; node = node->next)
    {
      // Inject JMP instruction
      BYTE *location = (BYTE*)((DWORD)root + (DWORD)node->origFunc);
      BYTE *newFunction = (BYTE*)node->newFunc;

      DWORD dwOldProtection;
      VirtualProtect(location, 5, PAGE_EXECUTE_READWRITE, &dwOldProtection);
      location[0] = 0xE9; //jmp
      *((DWORD*)(location + 1)) = (DWORD)(((DWORD)newFunction - (DWORD)location) - 5);
      VirtualProtect(location, 5, dwOldProtection, &dwOldProtection);
    }
  }
} decompPatchList;

// Function called to add a patch to the list of patches
void DecompPatchAdd(void *origFunc, void *newFunc)
{
  // Add to list
  decompPatchList.Add(origFunc, newFunc);
}

// Exported "Patch" function
// This goes through all our added patches and applies them
// Root is the root address of LEGO1.DLL
extern "C" __declspec(dllexport) void Patch(void *root)
{
  // Apply all patches
  decompPatchList.Patch(root);
}

#endif
