/* PID controller — tests FPU operations, struct access, function calls.
 * Tests: float arithmetic, struct field access, conditional branches, function args.
 */

typedef struct {
    float kp;
    float ki;
    float kd;
    float integral;
    float prev_error;
    float output;
    float out_min;
    float out_max;
} PID_t;

void pid_init(PID_t *pid, float kp, float ki, float kd)
{
    pid->kp = kp;
    pid->ki = ki;
    pid->kd = kd;
    pid->integral = 0.0f;
    pid->prev_error = 0.0f;
    pid->output = 0.0f;
    pid->out_min = -1.0f;
    pid->out_max = 1.0f;
}

float pid_compute(PID_t *pid, float setpoint, float measurement, float dt)
{
    float error = setpoint - measurement;
    float p_term = pid->kp * error;

    pid->integral += error * dt;
    float i_term = pid->ki * pid->integral;

    float derivative = (error - pid->prev_error) / dt;
    float d_term = pid->kd * derivative;

    pid->prev_error = error;
    pid->output = p_term + i_term + d_term;

    /* Clamp output */
    if (pid->output > pid->out_max)
        pid->output = pid->out_max;
    else if (pid->output < pid->out_min)
        pid->output = pid->out_min;

    return pid->output;
}

int main(void)
{
    volatile float r = run_pid_loop();
    (void)r;
    for (;;) {}
}

float run_pid_loop(void)
{
    PID_t controller;
    pid_init(&controller, 1.0f, 0.1f, 0.01f);

    float result = 0.0f;
    int i;
    for (i = 0; i < 100; i++) {
        result = pid_compute(&controller, 10.0f, result, 0.001f);
    }
    return result;
}
