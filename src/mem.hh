#ifndef MEM_HH
#define MEM_HH

#include <vm.hh>
#include <cstdlib>
#include <vector>
#include <stdint.h>
#include <boost/shared_ptr.hpp>

namespace Mem {

extern const std::size_t SLAB_SIZE;

struct Slab {
    Slab();

    uint64_t *base;
    uint64_t *free;
};

class MemState {
public:
    MemState();

    struct Allocation {
        uint64_t untagged;
        uint64_t tagged;
    };
    Allocation alloc_tagged_mem(std::size_t size, unsigned tag, unsigned second_tag);

private:
    void *alloc_mem(std::size_t size);

    std::vector<boost::shared_ptr<Slab> > slabs;
    std::size_t slab_size;
};

template <class FuncT>
void walk_stack(uint64_t base_pointer, uint64_t stop_pointer, FuncT func);

}

#include <mem.hxx>

#endif
