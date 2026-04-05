/* Combined source for F28335 flash image testing.
 *
 * Includes all 4 synthetic test apps with renamed main() functions.
 * A master main() calls all app entry points sequentially.
 * Compiled with cl2000 for F28335 flash addresses (COFF ABI).
 *
 * Functions included (21 total):
 *   led_blink:    led_main, delay, gpio_toggle
 *   pid_loop:     pid_main, pid_init, pid_compute, run_pid_loop
 *   switch_table: switch_main, process_command, run_commands
 *   isr_handler:  isr_main, buf_init, buf_put, buf_get, sci_rx_isr, process_received
 *   master:       main
 */

/* ── led_blink ── */
#define main led_main
#include "led_blink.c"
#undef main

/* ── pid_loop ── */
#define main pid_main
#include "pid_loop.c"
#undef main

/* ── switch_table ── */
#define main switch_main
#include "switch_table.c"
#undef main

/* ── isr_handler ── */
#define main isr_main
#include "isr_handler.c"
#undef main

/* Forward declarations to prevent implicit declaration warnings */
float run_pid_loop(void);
void run_commands(void);
unsigned int process_received(void);

/* ── Master entry point ──
 * Calls each app's key functions directly to ensure all code is reachable.
 * Each app_main() contains an infinite loop, so we call the interesting
 * sub-functions individually instead.
 */
int main(void)
{
    /* led_blink functions */
    gpio_toggle(0);
    delay(100);

    /* pid_loop functions */
    {
        PID_t ctrl;
        pid_init(&ctrl, 1.0f, 0.1f, 0.01f);
        volatile float r = pid_compute(&ctrl, 10.0f, 0.0f, 0.001f);
        (void)r;
    }

    /* switch_table functions */
    {
        volatile int r = process_command(0, 42, 7);
        (void)r;
    }

    /* isr_handler functions */
    buf_init();
    buf_put(0x55);
    {
        unsigned int d;
        buf_get(&d);
    }

    /* Ensure the app mains are not dead-code eliminated */
    volatile int (*app_mains[])(void) = {
        (int (*)(void))led_main,
        (int (*)(void))pid_main,
        (int (*)(void))switch_main,
        (int (*)(void))isr_main,
    };
    (void)app_mains;

    for (;;) {}
}
