#ifndef MXHASHTABLE_H
#define MXHASHTABLE_H

#include "mxcore.h"
#include "mxtypes.h"

#define HASH_TABLE_INIT_SIZE 128
#define HASH_TABLE_OPT_NO_EXPAND 0
#define HASH_TABLE_OPT_EXPAND_ADD 1
#define HASH_TABLE_OPT_EXPAND_MULTIPLY 2

template <class T>
class MxHashTableCursor;

template <class T>
class MxHashTableNode {
public:
	MxHashTableNode<T>() {}
	MxHashTableNode<T>(T* p_obj, MxU32 p_hash)
	{
		m_obj = p_obj;
		m_hash = p_hash;
		m_prev = NULL;
		m_next = NULL;
	}

	// private:
	T* m_obj;
	MxU32 m_hash;
	MxHashTableNode* m_prev;
	MxHashTableNode* m_next;
};

// See MxOmni::Create
// VTABLE 0x100dc1b0
template <class T>
class HashTableParent : public MxCore {
public:
	HashTableParent()
	{
		m_numKeys = 0;
		m_customDestructor = Destroy;
	}

	static void Destroy(T*){};

	virtual MxS8 Compare(T*, T*) = 0;

protected:
	MxU32 m_numKeys;                // +0x8
	void (*m_customDestructor)(T*); // +0xc
};

// VTABLE 0x100dc1e8
template <class T>
class MxHashTable : protected HashTableParent<T> {
public:
	MxHashTable()
	{
		m_numSlots = HASH_TABLE_INIT_SIZE;
		m_slots = new MxHashTableNode<T>*[HASH_TABLE_INIT_SIZE];
		memset(m_slots, 0, sizeof(MxHashTableNode<T>*) * m_numSlots);
		m_resizeOption = HASH_TABLE_OPT_NO_EXPAND;
	}

	virtual ~MxHashTable();

	void Resize();
	void Add(T*);

	virtual MxS8 Compare(T*, T*) = 0;

	virtual MxU32 Hash(T*) = 0;

	// FIXME: use of friend here?
	friend class MxHashTableCursor<T>;

protected:
	void _NodeInsert(MxHashTableNode<T>*);

	MxHashTableNode<T>** m_slots; // +0x10
	MxU32 m_numSlots;             // +0x14
	MxU32 m_autoResizeRatio;
	int m_resizeOption; // +0x1c
	// FIXME: or FIXME? This qword is used as an integer or double depending
	// on the value of m_resizeOption. Hard to say whether this is how the devs
	// did it, but a simple cast in either direction doesn't match.
	union {
		MxU32 m_increaseAmount;
		double m_increaseFactor;
	};
};

template <class T>
class MxHashTableCursor : public MxCore {
public:
	MxHashTableCursor(MxHashTable<T>* p_hashTable)
	{
		m_table = p_hashTable;
		m_match = NULL;
	}

	MxBool Find(T* p_obj)
	{
		MxU32 hash = m_table->Hash(p_obj);
		int bucket = hash % m_table->m_numSlots;

		MxHashTableNode<T>* t = m_table->m_slots[bucket];

		while (t) {
			if (t->m_hash == hash && !m_table->Compare(t->m_obj, p_obj))
				m_match = t;
			t = t->m_next;
		}

		return m_match != NULL;
	}

	void GetMatch(T*& p_obj)
	{
		if (m_match) {
			p_obj = m_match->m_obj;
		}
	}

	void DeleteMatch()
	{
		// Cut the matching node out of the linked list
		// by updating pointer references.

		if (m_match->m_prev) {
			m_match->m_prev->m_next = m_match->m_next;
		}
		else {
			// No "prev" node, so move "next" to the head of the list.
			int bucket = m_match->m_hash % m_table->m_numSlots;
			m_table->m_slots[bucket] = m_match->m_next;
		}

		if (m_match->m_next)
			m_match->m_next->m_prev = m_match->m_prev;

		m_table->m_customDestructor(m_match->m_obj);
		delete m_match;
		m_table->m_numKeys--;
	}

private:
	MxHashTable<T>* m_table;
	MxHashTableNode<T>* m_match;
};

template <class T>
MxHashTable<T>::~MxHashTable()
{
	for (int i = 0; i < m_numSlots; i++) {
		MxHashTableNode<T>* t = m_slots[i];

		while (t) {
			MxHashTableNode<T>* next = t->m_next;
			this->m_customDestructor(t->m_obj);
			delete t;
			t = next;
		}
	}

	this->m_numKeys = 0;
	memset(m_slots, 0, sizeof(MxHashTableNode<T>*) * m_numSlots);

	delete[] m_slots;
}

template <class T>
inline void MxHashTable<T>::Resize()
{
	// Save a reference to the current table
	// so we can walk nodes and re-insert
	MxU32 old_size = m_numSlots;
	MxHashTableNode<T>** old_table = m_slots;

	switch (m_resizeOption) {
	case HASH_TABLE_OPT_EXPAND_ADD:
		m_numSlots += m_increaseAmount;
		break;
	case HASH_TABLE_OPT_EXPAND_MULTIPLY:
		m_numSlots *= m_increaseFactor;
		break;
	}

	MxHashTableNode<T>** new_table = new MxHashTableNode<T>*[m_numSlots];
	// FIXME: order? m_numKeys set after `rep stosd`
	m_slots = new_table;
	memset(m_slots, 0, sizeof(MxHashTableNode<T>*) * m_numSlots);
	this->m_numKeys = 0;

	for (int i = 0; i != old_size; i++) {
		MxHashTableNode<T>* t = old_table[i];

		while (t) {
			MxHashTableNode<T>* next = t->m_next;
			_NodeInsert(t);
			t = next;
		}
	}

	delete[] old_table;
}

template <class T>
inline void MxHashTable<T>::_NodeInsert(MxHashTableNode<T>* p_node)
{
	int bucket = p_node->m_hash % m_numSlots;

	p_node->m_next = m_slots[bucket];

	if (m_slots[bucket])
		m_slots[bucket]->m_prev = p_node;

	m_slots[bucket] = p_node;
	this->m_numKeys++;
}

template <class T>
inline void MxHashTable<T>::Add(T* p_newobj)
{
	if (m_resizeOption && ((this->m_numKeys + 1) / m_numSlots) > m_autoResizeRatio)
		MxHashTable<T>::Resize();

	MxU32 hash = Hash(p_newobj);
	MxHashTableNode<T>* node = new MxHashTableNode<T>(p_newobj, hash);

	MxHashTable<T>::_NodeInsert(node);
}

#endif // MXHASHTABLE_H
