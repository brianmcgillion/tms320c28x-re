/* nested_conditions — 3+ levels of if/else if/else.
 * HLIL goal: clean nested-if structure with comparisons as `a == b` etc.
 * Watch for: cond:0 boolean reuse, where multiple compares overwrite
 *            the same temporary and HLIL renders broken conditions.
 */

volatile int sink;

int classify(int x)
{
    if (x < 0) {
        if (x < -100) {
            return -3;
        } else if (x < -10) {
            return -2;
        } else {
            return -1;
        }
    } else if (x == 0) {
        return 0;
    } else {
        if (x > 100) {
            return 3;
        } else if (x > 10) {
            return 2;
        } else {
            return 1;
        }
    }
}

int main(void)
{
    sink = classify(42);
    return sink;
}
