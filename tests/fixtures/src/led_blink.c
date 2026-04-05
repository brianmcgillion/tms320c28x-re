/* LED blink — simplest possible C28x program.
 * Tests: function prologue/epilogue, loops, memory-mapped I/O, basic branches.
 */

#define GPIO_DATA_REGS ((volatile unsigned int *)0x6F80)
#define GPIO_TOGGLE    (*(volatile unsigned int *)(0x6F80 + 6))

void delay(unsigned long count)
{
    volatile unsigned long i;
    for (i = 0; i < count; i++) {
        /* spin */
    }
}

void gpio_toggle(unsigned int pin)
{
    GPIO_TOGGLE = (1u << pin);
}

int main(void)
{
    while (1) {
        gpio_toggle(0);
        delay(100000);
    }
}
