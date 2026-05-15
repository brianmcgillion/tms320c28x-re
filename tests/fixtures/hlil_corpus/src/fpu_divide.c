/* fpu_divide — float division forces a LCR __c28xabi_divf at -O0.
 * HLIL goal: division shows as `a / b`, divf appears as a separate function.
 * Watch for: unimplemented stubs around the FPU register save/restore.
 */

volatile float fa;
volatile float fb;
volatile float fr;

float divide(float a, float b)
{
    return a / b;
}

float compute(void)
{
    return divide(fa, fb) + 1.0f;
}

int main(void)
{
    fr = compute();
    return (int)fr;
}
