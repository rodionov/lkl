#ifndef _LKL_SCHEDULER_H
#define _LKL_SCHEDULER_H

#include <set>
#include <fuzzer/FuzzedDataProvider.h>

class Scheduler {
    public:
	Scheduler(size_t num_tasks, unsigned int seed, const char *sched_data,
		  size_t sched_size);
	~Scheduler();

	void Join(void *task);
	void Leave(void *task);

	void *GetRandomTask();

	int Yield(void *task);
	void *SelectNextTask();

    private:
	FuzzedDataProvider *fdp_;
	std::set<void *> runnable_tasks_;
	std::set<void *> tasks_;

	int num_max_tasks_;
	int num_joined_tasks_;
	bool start_;

	void *current_task_;
	struct lkl_mutex *lock_;
};

#endif /* _LKL_SCHEDULER_H */
