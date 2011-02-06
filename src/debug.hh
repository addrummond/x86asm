#ifndef DEBUG_HH
#define DEBUG_HH

#ifdef DEBUG

namespace Debug {
void register_single_stepping_signal_handler(bool go_into_functions=true);
void unregister_single_stepping_signal_handler();
bool single_stepping_signal_handler_is_registered();
}

#endif

#endif
