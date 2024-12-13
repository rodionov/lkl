extern "C" {
#define new extern_new
#include <lkl_host.h>
#undef new
}

#include "lkl_random_sched.h"
#include "scheduler.h"

static Scheduler *g_scheduler;

static int do_yield(void *task)
{
	if (g_scheduler) {
		return g_scheduler->Yield(task);
	}
	return 0;
}

static void *select_next_task(void)
{
	if (g_scheduler) {
		return g_scheduler->SelectNextTask();
	}
	return NULL;
}

struct lkl_random_sched_ops lkl_random_sched = {
	.do_yield = do_yield,
	.select_next_task = select_next_task,
};

void lkl_random_sched_init(size_t num_tasks, unsigned int seed,
			   const char *sched_data, size_t sched_size)
{
	g_scheduler = new Scheduler(num_tasks, seed, sched_data, sched_size);
}

void lkl_random_sched_fini(void)
{
	delete g_scheduler;
}

/* This function expects the host task is created for the current thread by
 * performing syscall at least once. */
void lkl_random_sched_join(void)
{
	void *task = lkl_get_task();

	g_scheduler->Join(task);
}

void lkl_random_sched_leave(void)
{
	void *task = lkl_get_task();

	g_scheduler->Leave(task);
}
