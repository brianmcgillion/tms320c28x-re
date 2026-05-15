/* multi_return — return a small struct (forces multi-register ABI return).
 * HLIL goal: caller sees `r = compute()` with both fields populated.
 * Watch for: callee returns split across AL/AH/XAR4 etc; HLIL may show
 *            `unimplemented` for the result decomposition.
 */

typedef struct {
    int hi;
    int lo;
} Pair;

volatile int sink;

Pair make_pair(int x, int y)
{
    Pair p;
    p.hi = x + y;
    p.lo = x - y;
    return p;
}

int sum_pair(Pair p)
{
    return p.hi + p.lo;
}

int main(void)
{
    Pair p = make_pair(7, 3);
    sink = sum_pair(p);
    return sink;
}
