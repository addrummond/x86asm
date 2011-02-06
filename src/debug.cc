#ifdef DEBUG

#include <debug.hh>
#include <myassert.hh>
#include <cstring>
#include <cstdio>

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

    ud_t ud;
    ud_init(&ud);
    ud_set_input_buffer(&ud, (uint8_t *)(si->si_addr), 10);
    ud_set_mode(&ud, 64);
    ud_set_syntax(&ud, UD_SYN_INTEL);
    ud_disassemble(&ud);

    std::printf("About to exec: %s\nPress return to continue.\n", ud_insn_asm(&ud));
    while (std::getchar() != '\n');
}

void Debug::register_single_stepping_signal_handler()
{
    struct sigaction act;
    std::memset(&act, 0, sizeof(act));
    act.sa_sigaction = debug_signal_handler;
    act.sa_flags = SA_SIGINFO;
    if (sigaction(SIGTRAP, &act, NULL/*don't store old action info*/)) {
        assert(false);
    }
}

#endif
