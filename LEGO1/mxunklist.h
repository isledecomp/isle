#ifndef MXUNKLIST_H
#define MXUNKLIST_H

#include "decomp.h"
#include "mxtypes.h"

/*
* This is an as-of-yet unknown list-like data structure.
* The class hierarchy/structure isn't quite correct yet.
*/

struct MxUnkListNode {
  MxUnkListNode *m_unk00;
  MxUnkListNode *m_unk04;
  undefined4 m_unk08;
};

class MxUnkList {
public:
  inline MxUnkList() {
    undefined unk;
    this->m_unk00 = unk;

    MxUnkListNode *node = new MxUnkListNode();
    node->m_unk00 = node;
    node->m_unk04 = node;
    
    this->m_head = node;
    this->m_count = 0;
  }

  undefined m_unk00;
  MxUnkListNode *m_head;
  MxU32 m_count;
};

#endif // MXUNKLIST_H