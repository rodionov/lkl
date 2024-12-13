#ifndef _ASM_LKL_RANDOM_SCHED_H
#define _ASM_LKL_RANDOM_SCHED_H

#include <linux/sched.h>
#include <linux/kasan.h>
#include <uapi/asm/host_ops.h>
#include <asm/cpu.h>

static inline void thread_random_yield_jb(void)
{
	struct thread_info *ti = current_thread_info();

	//BUG_ON(!test_ti_thread_flag(ti, TIF_HOST_THREAD));
    if (!test_ti_thread_flag(ti, TIF_HOST_THREAD))
        return;

	while (lkl_ops->random_sched_ops->do_yield(current)) {
		struct task_struct *next;

		set_current_state(TASK_UNINTERRUPTIBLE);
		next = lkl_ops->random_sched_ops->select_next_task();
		if (next) {
			wake_up_process(next);
		}
		schedule();
	}
}

static inline void _spin_lock(spinlock_t *lock)
{
	// Use `arch_spin_is_locked` because calling `spin_trylock` on an acquired
	// spinlock will cause kernel panic because LKL does not support SMP and
	// preemption, so UP build does not expect kernel to wait for spinlock.
	while (arch_spin_is_locked(&lock->rlock.raw_lock)) {
		thread_random_yield_jb();
	}
	spin_lock(lock);
}

static inline void _spin_unlock(spinlock_t *lock)
{
	spin_unlock(lock);
	thread_random_yield_jb();
}

static inline void _mutex_lock(struct mutex *lock)
{
	while (!mutex_trylock(lock)) {
		thread_random_yield_jb();
	}
}

static inline void _mutex_unlock(struct mutex *lock)
{
	mutex_unlock(lock);
	thread_random_yield_jb();
}

// Macros to replace existing spinlock and mutex implementations
// TODO: evaluate if instrumenting spinlocks also works for fuzzing
// although yelding execution upon acquired spinlock isn't correct.
// #define spin_lock _spin_lock
// #define spin_unlock _spin_unlock
#define mutex_lock _mutex_lock
#define mutex_unlock _mutex_unlock

#endif /*  _ASM_LKL_RANDOM_SCHED_H */
