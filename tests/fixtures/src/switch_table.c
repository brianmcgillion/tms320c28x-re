/* Switch statement — tests jump table generation.
 * Tests: switch/case, jump tables, integer comparisons, function pointers.
 */

volatile int result;

int process_command(int cmd, int arg1, int arg2)
{
    switch (cmd) {
    case 0:  return arg1 + arg2;
    case 1:  return arg1 - arg2;
    case 2:  return arg1 * arg2;
    case 3:  return arg1 & arg2;
    case 4:  return arg1 | arg2;
    case 5:  return arg1 ^ arg2;
    case 6:  return arg1 << (arg2 & 0xF);
    case 7:  return arg1 >> (arg2 & 0xF);
    default: return -1;
    }
}

int main(void)
{
    run_commands();
    for (;;) {}
}

void run_commands(void)
{
    int i;
    for (i = 0; i < 8; i++) {
        result = process_command(i, 42, 7);
    }
}
