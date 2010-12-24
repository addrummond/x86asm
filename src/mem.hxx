template <class FuncT>
void Mem::walk_stack(uint64_t base_pointer, uint64_t stop_pointer, FuncT func)
{
    while (base_pointer < stop_pointer) { // Remember that the stack grows down on x86.
        uint64_t return_addr = reinterpret_cast<uint64_t *>(base_pointer)[1];
        func(return_addr);
        base_pointer = *reinterpret_cast<uint64_t *>(base_pointer);
    }
}
