#ifndef MXLIST_H
#define MXLIST_H

#include "mxtypes.h"
#include "mxcore.h"

template <class T>
// SIZE 0xc
class MxListEntry
{
public:
  MxListEntry() {}
  MxListEntry(T *p_obj, MxListEntry *p_prev) {
    m_obj = p_obj;
    m_prev = p_prev;
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
  // OFFSET: LEGO1 0x1001cdd0
  virtual ~MxListParent() {}

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

  void Append(T*);
protected:
  MxListEntry<T> *m_first; // +0x10
  MxListEntry<T> *m_last;  // +0x14
};

template <class T>
// OFFSET: LEGO1 0x1001ce20
MxList<T>::~MxList()
{
  for (MxListEntry<T> *t = m_first;;) {
    if (!t)
      break;

    MxListEntry<T> *next = t->m_next;
    m_customDestructor(t->m_obj);
    delete t;
    t = next;
  }

  m_count = 0;
  m_last = NULL;
  m_first = NULL;
}

template <class T>
inline void MxList<T>::Append(T *p_newobj)
{
  MxListEntry<T> *currentLast = this->m_last;
  MxListEntry<T> *newEntry = new MxListEntry<T>(p_newobj, currentLast);

  if (currentLast)
    currentLast->m_next = newEntry;
  else
    this->m_first = newEntry;
    
  this->m_last = newEntry;
  this->m_count++;
}

#endif // MXLIST_H