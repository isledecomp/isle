#ifndef MXLIST_H
#define MXLIST_H

#include "mxtypes.h"
#include "mxcore.h"

template <class T>
class MxListEntry
{
public:
  MxListEntry<T>() {}
  MxListEntry<T>(T *p_obj) {
    m_obj = p_obj;
    m_prev = NULL;
    m_next = NULL;
  }

  T *m_obj;
  MxListEntry *m_prev;
  MxListEntry *m_next;
};

// VTABLE 0x100d6350
// SIZE 0x10
template <class T>
class MxListParent : public MxCore
{
public:
  MxListParent() {
    m_count = 0;
    m_customDestructor = Destroy;
  }

  // OFFSET: LEGO1 0x1001cd30
  static void Destroy(T *) {};

  // OFFSET: LEGO1 0x1001cd20
  virtual MxS8 Compare(T *, T *) = 0;

protected:
  MxU32 m_count;                   // +0x8
  void (*m_customDestructor)(T *); // +0xc
};

// VTABLE 0x100d6368
// SIZE 0x18
template <class T>
class MxList : protected MxListParent<T>
{
public:
  MxList() {
    m_last = NULL;
    m_first = NULL;
  }

  virtual ~MxList();
protected:
  MxListEntry<T> *m_first; // +0x10
  MxListEntry<T> *m_last;  // +0x14
};

template <class T>
// OFFSET: LEGO1 0x1001cfe0
MxList<T>::~MxList()
{
  MxListEntry<T> *t = m_first;

  while (t) {
    MxListEntry<T> *next = t->m_next;
    m_customDestructor(t->m_obj);
    delete t;
    t = next;
  }

  m_count = 0;
  m_last = NULL;
  m_first = NULL;
}

#endif // MXLIST_H