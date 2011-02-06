#ifndef DEBUG_HH
#define DEBUG_HH

#ifdef DEBUG

namespace Debug {
void register_single_stepping_signal_handler();
void unregister_single_stepping_signal_handler();
}

#endif

#endif
