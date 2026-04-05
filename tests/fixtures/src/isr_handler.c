/* Interrupt handler — tests ISR entry/exit, volatile access, ring buffer.
 * Tests: interrupt keyword, volatile memory access, circular buffer pattern.
 */

#define BUF_SIZE 16
#define BUF_MASK (BUF_SIZE - 1)

volatile unsigned int rx_buf[BUF_SIZE];
volatile unsigned int rx_head;
volatile unsigned int rx_tail;
volatile unsigned int rx_count;

/* Simulated SCI data register */
#define SCI_RXBUF (*(volatile unsigned int *)0x7050)

void buf_init(void)
{
    rx_head = 0;
    rx_tail = 0;
    rx_count = 0;
}

int buf_put(unsigned int data)
{
    if (rx_count >= BUF_SIZE)
        return -1;  /* full */
    rx_buf[rx_head] = data;
    rx_head = (rx_head + 1) & BUF_MASK;
    rx_count++;
    return 0;
}

int buf_get(unsigned int *data)
{
    if (rx_count == 0)
        return -1;  /* empty */
    *data = rx_buf[rx_tail];
    rx_tail = (rx_tail + 1) & BUF_MASK;
    rx_count--;
    return 0;
}

__interrupt void sci_rx_isr(void)
{
    unsigned int data = SCI_RXBUF;
    buf_put(data);
}

int main(void)
{
    buf_init();
    volatile unsigned int s = process_received();
    (void)s;
    for (;;) {}
}

unsigned int process_received(void)
{
    unsigned int data;
    unsigned int sum = 0;
    while (buf_get(&data) == 0) {
        sum += data;
    }
    return sum;
}
