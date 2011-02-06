#ifdef DEBUG

#include <debug.hh>
#include <myassert.hh>
#include <cstring>
#include <cstdio>
#include <cstdlib>

extern "C" {
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/signal.h>
#ifdef CONFIG_UDIS86
#    include <udis86.h>
#endif
}

static void debug_signal_handler(int signal, siginfo_t *si, void *uctx)
{
    assert(signal == SIGTRAP);

#ifdef CONFIG_UDIS86
    ud_t ud;
    ud_init(&ud);
    ud_set_input_buffer(&ud, (uint8_t *)(si->si_addr), 10);
    ud_set_mode(&ud, 64);
    ud_set_syntax(&ud, UD_SYN_INTEL);
    ud_disassemble(&ud);
    std::printf("About to exec: %s\nPress return to continue", ud_insn_asm(&ud));
#else
    std::printf("[Some instruction -- not linked to udis86]\nPress return to continue");
#endif

    while (std::getchar() != '\n');
}

// Obviously, the checks involving 'is_registered' below aren't strictly correct,
// since signals are asynchronous and there's no guarantee that 'is_registered' will
// be in a consistent state. However, it should be good enough to catch a few bugs.
static bool is_registered; // Guaranteed to be initialized to false.
static struct sigaction old_act;
void Debug::register_single_stepping_signal_handler()
{
    assert(! is_registered);

    struct sigaction act;
    std::memset(&act, 0, sizeof(act));
    act.sa_sigaction = debug_signal_handler;
    act.sa_flags = SA_SIGINFO;
    if (sigaction(SIGTRAP, &act, &old_act)) {
        std::fprintf(stderr, "ERROR: Unable to register single stepping signal handler for SIGTRAP.\n");
        exit(1);
    }
    is_registered = true;
}

void Debug::unregister_single_stepping_signal_handler()
{
    assert(is_registered);

    if (sigaction(SIGTRAP, &old_act, NULL)) {
        std::fprintf(stderr, "ERROR: Unable to unregister single stepping signal handler for SIGTRAP.\n");
        std::exit(1);
    }
    is_registered = false;
}

#endif
