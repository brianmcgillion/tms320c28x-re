/* Minimal linker command file for test fixtures.
 * Maps to a generic C28x memory layout.
 */

MEMORY
{
    FLASH  : origin = 0x080000, length = 0x040000   /* 256K words */
    RAMLS  : origin = 0x008000, length = 0x002000   /*   8K words */
    RAMGS  : origin = 0x00C000, length = 0x008000   /*  32K words */
    STACK  : origin = 0x000400, length = 0x000400   /* 1K words   */
}

SECTIONS
{
    .text     : > FLASH,  ALIGN(2)
    .cinit    : > FLASH,  ALIGN(2)
    .switch   : > FLASH,  ALIGN(2)
    .const    : > FLASH,  ALIGN(2)
    .econst   : > FLASH,  ALIGN(2)
    .pinit    : > FLASH,  ALIGN(2)

    .bss      : > RAMLS
    .data     : > RAMLS
    .ebss     : > RAMGS
    .esysmem  : > RAMGS
    .stack    : > STACK
    .sysmem   : > RAMGS
}
