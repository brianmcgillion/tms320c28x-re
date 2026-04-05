/* F28335 flash linker script for combined test image.
 * Places all code in flash sectors G-A for flash.py validation.
 */

MEMORY
{
    FLASHH  : origin = 0x300000, length = 0x008000
    FLASHG  : origin = 0x308000, length = 0x008000
    FLASHF  : origin = 0x310000, length = 0x008000
    FLASHE  : origin = 0x318000, length = 0x008000
    FLASHD  : origin = 0x320000, length = 0x008000
    FLASHC  : origin = 0x328000, length = 0x008000
    FLASHB  : origin = 0x330000, length = 0x008000
    FLASHA  : origin = 0x338000, length = 0x007F80
    BEGIN   : origin = 0x33FFF6, length = 0x000002

    RAMM0   : origin = 0x000050, length = 0x0003B0
    RAMM1   : origin = 0x000400, length = 0x000400
    RAML4   : origin = 0x00C000, length = 0x004000
}

SECTIONS
{
    .text     : > FLASHG,  ALIGN(2)
    .cinit    : > FLASHG,  ALIGN(2)
    .const    : > FLASHF,  ALIGN(2)
    .econst   : > FLASHF,  ALIGN(2)
    .switch   : > FLASHF,  ALIGN(2)
    .pinit    : > FLASHG,  ALIGN(2)

    .bss      : > RAML4
    .ebss     : > RAML4
    .data     : > RAML4
    .stack    : > RAMM1
    .esysmem  : > RAML4
    .sysmem   : > RAML4

    .reset    : > FLASHH, TYPE = DSECT
}
