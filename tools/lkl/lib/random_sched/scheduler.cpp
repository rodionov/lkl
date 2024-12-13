#include <assert.h>
#include <stdlib.h>

extern "C" {
#define new extern_new
#include <lkl_host.h>
#undef new
}

#include "scheduler.h"

Scheduler::Scheduler(size_t num_tasks, unsigned int seed,
		     const char *sched_data, size_t sched_size)
	: num_max_tasks_(num_tasks), num_joined_tasks_(0), start_(false),
	  current_task_(NULL)
{
	lock_ = lkl_host_ops.mutex_alloc(0);

	fdp_ = new FuzzedDataProvider((const unsigned char *)sched_data,
				      sched_size);
	srand(seed);
}

Scheduler::~Scheduler()
{
	free(fdp_);
	lkl_host_ops.mutex_free(lock_);
}

void Scheduler::Join(void *task)
{
	lkl_host_ops.mutex_lock(lock_);
	tasks_.insert(task);
	num_joined_tasks_++;

	// Start the randomized scheduler and schedule next task
	if (num_joined_tasks_ == num_max_tasks_) {
		start_ = true;
		current_task_ = GetRandomTask();
	}
	assert(num_joined_tasks_ <= num_max_tasks_);
	lkl_host_ops.mutex_unlock(lock_);
}

void Scheduler::Leave(void *task)
{
	lkl_host_ops.mutex_lock(lock_);
	tasks_.erase(task);
	runnable_tasks_.erase(task);

	// Schedule next task if the caller host task is the current task
	if (current_task_ == task && tasks_.size() > 0) {
		current_task_ = GetRandomTask();
	}
	lkl_host_ops.mutex_unlock(lock_);
}

// TODO(zifantan): This is not deterministic because tasks are sorted
// differently in the set.
void *Scheduler::GetRandomTask()
{
	void *task;
	size_t idx;
	size_t upper_bound = tasks_.size();

	if (fdp_->remaining_bytes()) {
		idx = fdp_->ConsumeIntegralInRange<unsigned char>(
			0, upper_bound - 1);
	} else {
		idx = (unsigned int)rand() % upper_bound;
	}

	auto it = tasks_.begin();
	while (idx--) {
		it++;
	}
	task = *it;

	return task;
}

int Scheduler::Yield(void *task)
{
	runnable_tasks_.erase(task);

	// Do not yield when randomized scheduling has not started or the caller host
	// task is not in the thread pool.
	if (!start_ || tasks_.find(task) == tasks_.end())
		return 0;

	// Do not yield when there is only one task in the thread pool.
	if (tasks_.size() == 1)
		return 0;

	// Do not yield and schedule next task if the caller host task is the current
	// task we want to schedule
	if (task == current_task_) {
		current_task_ = GetRandomTask();
		return 0;
	}

	runnable_tasks_.insert(task);
	return 1;
}

void *Scheduler::SelectNextTask()
{
	// Wake up the current task when all host tasks in the thread pool are
	// sleeping
	if (start_ && tasks_.size() > 0 &&
	    tasks_.size() == runnable_tasks_.size() &&
	    runnable_tasks_.find(current_task_) != runnable_tasks_.end()) {
		return current_task_;
	}

	return NULL;
}
