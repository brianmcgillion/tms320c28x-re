/* switch_compare_chain — 8-case switch.
 * At -O0, cl2000 lowers this to compare-and-branch chain (we saw this
 * in process_command analysis). At -O2 it may use a jump table.
 * HLIL goal: switch statement rendered cleanly with case bodies.
 * Watch for: phantom basic blocks from inline jump table data; case-body
 *            attribution to wrong function.
 */

volatile int sink;

int dispatch(int op, int a, int b)
{
    switch (op) {
    case 0:  return a + b;
    case 1:  return a - b;
    case 2:  return a * b;
    case 3:  return a & b;
    case 4:  return a | b;
    case 5:  return a ^ b;
    case 6:  return a << (b & 0xF);
    case 7:  return a >> (b & 0xF);
    default: return -1;
    }
}

int main(void)
{
    sink = dispatch(2, 7, 6);
    return sink;
}
