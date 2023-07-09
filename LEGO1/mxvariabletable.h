#ifndef MXVARIABLETABLE_H
#define MXVARIABLETABLE_H

#include "mxtypes.h"
#include "mxcore.h"
#include "mxvariable.h"

template <class T>
class MxHashTableNode
{
public:
  MxHashTableNode<T>() {}
  MxHashTableNode<T>(T *p_obj, MxU32 p_hash)
  {
    m_obj = p_obj;
    m_hash = p_hash;
    m_prev = NULL;
    m_next = NULL;
  }

//private:
  T* m_obj;
  MxU32 m_hash;
  MxHashTableNode *m_prev;
  MxHashTableNode *m_next;
};

template <class T>
class MxHashTable : public MxCore
{
public:
  MxHashTable()
  {
    m_size = 128;
    m_table = new MxHashTableNode<T>*[128];
  }

  ~MxHashTable()
  {
    delete[] m_table;
  }

  virtual MxS8 Compare(T*, T*);
  virtual MxU32 Hash(T*);

//private:
  int m_used; // +0x8
  void (*m_unkc)(void *); // +0xc
  MxHashTableNode<T> **m_table; // +0x10
  int m_size; // +0x14
  int m_unk18;
  int m_unk1c;
  int m_unk20;
  int m_unk24;
};

template <class T>
class MxHashTableCursor : public MxCore
{
public:
  MxHashTableCursor(MxHashTable<T> *p_hashTable)
  {
    m_hashTable = p_hashTable;
    m_match = NULL;
  }

  MxBool Find(T *p_obj)
  {
    MxU32 hash = m_hashTable->Hash(p_obj);
    int bucket = hash % m_hashTable->m_size;

    MxHashTableNode<T> *t = m_hashTable->m_table[bucket];

    while (t) {
      if (t->m_hash == hash && !m_hashTable->Compare(t->m_obj, p_obj))
        m_match = t;
      t = t->m_next;
    }

    return m_match != NULL;
  }

  void GetMatch(T **p_obj)
  {
    if (m_match)
      *p_obj = m_match->m_obj;
    //p_obj = m_match ? m_match->m_obj : NULL; // ?
  }

  /*
  T* GetMatch()
  {
    return m_match ? m_match->m_obj : NULL;
  }
  */

private:
  MxHashTable<T> *m_hashTable;
  MxHashTableNode<T> *m_match; // type ?
};

// VTABLE 0x100dc1c8
// SIZE 0x28
class MxVariableTable : protected MxHashTable<MxVariable>
{
public:
  __declspec(dllexport) const char * GetVariable(const char *key);
  __declspec(dllexport) void SetVariable(MxVariable *var);
  __declspec(dllexport) void SetVariable(const char *key, const char *value);

  virtual MxS8 Compare(MxVariable *, MxVariable *); // +0x14
  virtual MxU32 Hash(MxVariable *); // +0x18
};

#endif // MXVARIABLETABLE_H
