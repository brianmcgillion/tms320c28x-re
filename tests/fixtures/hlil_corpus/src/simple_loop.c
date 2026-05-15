/* simple_loop — counted loop with single comparison.
 * HLIL goal: clean `for (i = 0; i < n; i++)` or `do/while` pattern.
 * This is the CONTROL case — if HLIL fails here, the whole pipeline is broken.
 */

volatile int sink;

int sum_n(int n)
{
    int i;
    int total = 0;
    for (i = 0; i < n; i++) {
        total += i;
    }
    return total;
}

int main(void)
{
    sink = sum_n(10);
    return sink;
}
