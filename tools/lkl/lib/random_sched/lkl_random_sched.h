#ifndef _LKL_RANDOM_SCHED_H
#define _LKL_RANDOM_SCHED_H

void lkl_random_sched_init(size_t num_tasks, unsigned int seed,
			   const char *sched_data, size_t sched_size);
void lkl_random_sched_fini(void);
void lkl_random_sched_join(void);
void lkl_random_sched_leave(void);

#endif // _LKL_RANDOM_SCHED_H