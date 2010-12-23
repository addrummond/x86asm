#include <mem.hh>

using namespace Mem;

namespace {
    typedef std::vector<boost::shared_ptr<Slab> >::iterator SlabIt;
    typedef std::vector<boost::shared_ptr<Slab> >::const_iterator SlabConstIt;
}

const std::size_t Mem::SLAB_SIZE = 4028;

Mem::Slab::Slab()
{
    base = static_cast<uint64_t *>(std::malloc(SLAB_SIZE));
    free = base;
}

Mem::MemState::MemState()
{
    boost::shared_ptr<Slab> s(new Slab);
    slabs.push_back(s);
    slab_size = SLAB_SIZE;
}

void *Mem::MemState::alloc_mem(std::size_t size)
{
    for (SlabIt i = slabs.begin(); i < slabs.end(); ++i) {
        long long remaining = slab_size - reinterpret_cast<long long>((*i)->free);
        if (remaining >= size) {
            void *r = (*i)->free;
            (*i)->free += size;
            return r;
        }
    }

    boost::shared_ptr<Slab> s(new Slab);
    assert(size < slab_size);
    slabs.push_back(s);
    void *r = s->free;
    s->free += size;
    return r;
}

Mem::MemState::Allocation Mem::MemState::alloc_tagged_mem(std::size_t size, unsigned tag)
{
    assert(tag < 4);

    Allocation a;
    uint64_t *mem = static_cast<uint64_t *>(alloc_mem(size));
    a.untagged = reinterpret_cast<uint64_t>(mem);
    a.tagged = a.untagged | tag;
    return a;
}

template <class FuncT>
void walk_stack(uint64_t *base_pointer, uint64_t *stop_pointer, FuncT func)
{
    while (base_pointer < stop_pointer) { // Remember that the stack grows down on x86.
        uint64_t return_addr = base_pointer[1];
        func(return_addr);
        base_pointer = reinterpret_cast<uint64_t *>(*base_pointer);
    }
}
