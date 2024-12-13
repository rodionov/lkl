#include <assert.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

extern "C" {
#define new extern_new
#include <lkl.h>
#include <lkl_host.h>
#undef new
}

#include <fuzzer/FuzzedDataProvider.h>

#include "../../lib/random_sched/lkl_random_sched.h"
#include "src/libfuzzer/libfuzzer_macro.h"

#include "binder.h"
#include "binder.pb.h"

#define NUM_CLIENT 3
#define MAX_HANDLE 10
#define MAX_READ_BUF_SIZE 1024
#define MAX_EXTRA_BUF_SIZE 256
#define MAX_BINDER_BUF_OBJ_SIZE 32

#define LOG(fmt, ...)                                                          \
	if (g_log_enabled) {                                                   \
		printf(fmt, ##__VA_ARGS__);                                    \
	}

static bool g_log_enabled = true;

static int _check_binder_version()
{
	int ret;
	binder_ctx *ctx;

	ctx = binder_open();
	if (ctx == NULL) {
		return -1;
	}

	ret = binder_ioctl_check_version(ctx);

	binder_close(ctx);
	return ret;
}

static void _generate_binder_object(txnout_t *txnout, struct binder_object *bo,
				    const BinderObject &fuzz_bo)
{
	switch (fuzz_bo.type_case()) {
	case BinderObject::kBinder:
		bo->fbo = {
			.hdr = { .type = LKL_BINDER_TYPE_BINDER },
			.binder = fuzz_bo.binder().ptr() % MAX_HANDLE,
			.cookie = 0,
		};
		break;
	case BinderObject::kWeakBinder:
		bo->fbo = {
			.hdr = { .type = LKL_BINDER_TYPE_WEAK_BINDER },
			.binder = fuzz_bo.weak_binder().ptr() % MAX_HANDLE,
			.cookie = 0,
		};
		break;
	case BinderObject::kHandle:
		bo->fbo = {
			.hdr = { .type = LKL_BINDER_TYPE_HANDLE },
			.handle = fuzz_bo.handle() % MAX_HANDLE,
		};
		break;
	case BinderObject::kWeakHandle:
		bo->fbo = {
			.hdr = { .type = LKL_BINDER_TYPE_WEAK_HANDLE },
			.handle = fuzz_bo.handle() % MAX_HANDLE,
		};
		break;
	case BinderObject::kFd: {
		if (txnout->fd == -1) {
			txnout->fd = lkl_sys_open(
				".", LKL_O_RDONLY | LKL_O_DIRECTORY, 0);
		}
		bo->fdo = {
			.hdr = { .type = LKL_BINDER_TYPE_FD },
			.fd = (uint32_t)txnout->fd,
			.cookie = 0,
		};
	} break;
	case BinderObject::kFda: {
		// TODO(zifantan): Open files and add them to an array buffer
		bo->fdao = {
			.hdr = { .type = LKL_BINDER_TYPE_FDA },
			.num_fds = fuzz_bo.fda().num_fds(),
			.parent = fuzz_bo.fda().parent(),
			.parent_offset = fuzz_bo.fda().parent_offset(),
		};
	} break;
	case BinderObject::kPtr: {
		size_t buffer_size =
			fuzz_bo.ptr().buffer_size() % MAX_BINDER_BUF_OBJ_SIZE;
		void *bbo_buf = txnout_extra_buf_alloc(txnout, buffer_size);
		if (bbo_buf) {
			memcpy(bbo_buf, fuzz_bo.ptr().buffer().data(),
			       buffer_size);
		}

		bo->bbo = {
			.hdr = { .type = LKL_BINDER_TYPE_PTR },
			.flags =
				(uint32_t)(fuzz_bo.ptr().has_parent_flag() ?
						   LKL_BINDER_BUFFER_FLAG_HAS_PARENT :
						   0),
			.buffer = (lkl_binder_size_t)bbo_buf,
			.length = (lkl_binder_size_t)buffer_size,
			.parent = fuzz_bo.ptr().parent(),
			.parent_offset = fuzz_bo.ptr().parent_offset(),
		};
	} break;
	case BinderObject::TYPE_NOT_SET:
		break;
	}
}

static void _generate_transaction(bwr_buf_t *bb,
				  struct lkl_binder_transaction_data *tr,
				  const Transaction &fuzz_tr)
{
	txnout_t *txnout;
	struct binder_object *bo;

	txnout = (txnout_t *)malloc(sizeof(*txnout));
	txnout_init(txnout);

	// Generate random binder objects
	for (const BinderObject &fuzz_bo : fuzz_tr.binder_objects()) {
		bo = (struct binder_object *)txnout_alloc(txnout, sizeof(*bo));
		if (!bo) {
			break;
		}
		_generate_binder_object(txnout, bo, fuzz_bo);
	}

	tr->target.handle = fuzz_tr.target_handle() % MAX_HANDLE;
	for (const auto &flag : fuzz_tr.flags()) {
		tr->flags |= flag;
	}
	tr->data_size = txnout->data - txnout->data0;
	tr->offsets_size =
		((uint8_t *)txnout->offs) - ((uint8_t *)txnout->offs0);
	tr->data.ptr.buffer = (lkl_binder_uintptr_t)txnout->data0;
	tr->data.ptr.offsets = (lkl_binder_uintptr_t)txnout->offs0;

	// Introduce unaligned data and offsets size
	tr->data_size += fuzz_tr.extra_data_size() % RANDOM_SIZE_RANGE;
	tr->offsets_size += fuzz_tr.extra_offsets_size() % RANDOM_SIZE_RANGE;

	bb->txnouts.push_back(txnout);
}

static void
_generate_transaction_sg(bwr_buf_t *bb,
			 struct lkl_binder_transaction_data_sg *tr_sg,
			 const TransactionSg &fuzz_tr_sg)
{
	_generate_transaction(bb, &tr_sg->transaction_data,
			      fuzz_tr_sg.transaction());
	tr_sg->buffers_size =
		fuzz_tr_sg.extra_buffers_size() % MAX_EXTRA_BUF_SIZE;
}

static void _generate_bwr_buf(binder_ctx *ctx, bwr_buf_t *bb,
			      const BinderWrite &fuzz_binder_write)
{
	for (const BinderCommand &command :
	     fuzz_binder_write.binder_commands()) {
		switch (command.bc_case()) {
		case BinderCommand::kAcquire:
			bwr_buf_put_handle_req(bb,
					       command.acquire() % MAX_HANDLE,
					       LKL_BC_ACQUIRE);
			break;
		case BinderCommand::kIncrefs:
			bwr_buf_put_handle_req(bb,
					       command.increfs() % MAX_HANDLE,
					       LKL_BC_INCREFS);
			break;
		case BinderCommand::kRelease:
			bwr_buf_put_handle_req(bb,
					       command.release() % MAX_HANDLE,
					       LKL_BC_RELEASE);
			break;
		case BinderCommand::kDecrefs:
			bwr_buf_put_handle_req(bb,
					       command.decrefs() % MAX_HANDLE,
					       LKL_BC_DECREFS);
			break;
		case BinderCommand::kIncrefsDone:
			bwr_buf_put_binder_req(
				bb, command.increfs_done().ptr() % MAX_HANDLE,
				0, LKL_BC_INCREFS_DONE);
			break;
		case BinderCommand::kAcquireDone:
			bwr_buf_put_binder_req(
				bb, command.acquire_done().ptr() % MAX_HANDLE,
				0, LKL_BC_ACQUIRE_DONE);
			break;
		case BinderCommand::kTransaction: {
			struct lkl_binder_transaction_data *tr_data;

			tr_data = bwr_buf_alloc_transaction(bb, false);
			if (!tr_data) {
				break;
			}
			_generate_transaction(bb, tr_data,
					      command.transaction());
		} break;
		case BinderCommand::kReply: {
			struct lkl_binder_transaction_data *tr_data;

			tr_data = bwr_buf_alloc_transaction(bb, true);
			if (!tr_data) {
				break;
			}
			_generate_transaction(bb, tr_data,
					      command.transaction());
		} break;
		case BinderCommand::kTransactionSg: {
			struct lkl_binder_transaction_data_sg *tr_data_sg;

			tr_data_sg = bwr_buf_alloc_transaction_sg(bb, false);
			if (!tr_data_sg) {
				break;
			}
			_generate_transaction_sg(bb, tr_data_sg,
						 command.transaction_sg());
		} break;
		case BinderCommand::kReplySg: {
			struct lkl_binder_transaction_data_sg *tr_data_sg;

			tr_data_sg = bwr_buf_alloc_transaction_sg(bb, true);
			if (!tr_data_sg) {
				break;
			}
			_generate_transaction_sg(bb, tr_data_sg,
						 command.transaction_sg());
		} break;
		case BinderCommand::kFreeBuffer: {
			if (!ctx->buffers.empty()) {
				bwr_buf_put_free_buffer(bb,
							ctx->buffers.front());
				ctx->buffers.pop();
			} else {
				bwr_buf_put_free_buffer(bb, 0);
			}
		} break;
		case BinderCommand::kRequestDeathNotification:
			bwr_buf_put_death_notif_req(
				bb,
				command.request_death_notification().ptr() %
					MAX_HANDLE,
				0, LKL_BC_REQUEST_DEATH_NOTIFICATION);
			break;
		case BinderCommand::kClearDeathNotification:
			bwr_buf_put_death_notif_req(
				bb,
				command.clear_death_notification().ptr() %
					MAX_HANDLE,
				0, LKL_BC_CLEAR_DEATH_NOTIFICATION);
			break;
		case BinderCommand::kDeadBinderDone:
			bwr_buf_put_dead_binder_done(
				bb, command.dead_binder_done());
			break;
		case BinderCommand::kRegisterLooper:
			bwr_buf_put_bc(bb, LKL_BC_REGISTER_LOOPER);
			break;
		case BinderCommand::kEnterLooper:
			bwr_buf_put_bc(bb, LKL_BC_ENTER_LOOPER);
			break;
		case BinderCommand::kExitLooper:
			bwr_buf_put_bc(bb, LKL_BC_EXIT_LOOPER);
			break;
		case BinderCommand::BC_NOT_SET:
			break;
		}
	}
}

static int _ep_add_binder(binder_ctx *ctx)
{
	int ret;
	struct lkl_epoll_event ev = { .events = LKL_POLLIN };

	if (ctx->epoll_fd != -1)
		return -1;

	ctx->epoll_fd = lkl_sys_epoll_create(1);
	assert(ctx->epoll_fd != -1);

	ret = lkl_sys_epoll_ctl(ctx->epoll_fd, LKL_EPOLL_CTL_ADD, ctx->fd, &ev);
	assert(ret != -1);

	return 0;
}

static int _ep_wait_binder(binder_ctx *ctx)
{
	int ret;
	struct lkl_epoll_event ev;

	ret = lkl_sys_epoll_wait(ctx->epoll_fd, &ev, 1, 0);

	return ret;
}

static void perform_ioctls(binder_ctx *ctx, void *arg)
{
	bwr_buf_t bb;
	auto ioctls = *(const google::protobuf::RepeatedPtrField<Ioctl> *)arg;

	for (const Ioctl &ioctl : ioctls) {
		switch (ioctl.ioctl_case()) {
		case Ioctl::kBinderWrite:
			bwr_buf_init(&bb, 256);
			_generate_bwr_buf(ctx, &bb, ioctl.binder_write());
			binder_send(ctx, &bb);
			bwr_buf_fini(&bb);
			break;
		case Ioctl::kBinderRead: {
			binder_recv(ctx, MAX_READ_BUF_SIZE);
		} break;
		case Ioctl::kBinderThreadExit:
			binder_ioctl_thread_exit(ctx);
			break;
		case Ioctl::kBinderVersion:
			binder_ioctl_check_version(ctx);
			break;
		case Ioctl::kBinderGetNodeDebugInfo:
			binder_ioctl_get_node_debug_info(
				ctx, ioctl.binder_get_node_debug_info().ptr() %
					     MAX_HANDLE);
			break;
		case Ioctl::kBinderGetNodeInfoForRef:
			binder_ioctl_get_node_info_for_ref(
				ctx,
				ioctl.binder_get_node_info_for_ref().handle() %
					MAX_HANDLE);
			break;
		case Ioctl::kBinderEnableOnewaySpamDetection:
			binder_ioctl_enable_oneway_spam_detection(
				ctx,
				ioctl.binder_enable_oneway_spam_detection());
			break;
		case Ioctl::IOCTL_NOT_SET:
			break;
		}
	}
}

extern "C" void __llvm_profile_initialize_file(void);
extern "C" int __llvm_profile_write_file(void);

void flush_coverage()
{
	LOG("Flushing coverage data...\n");
	__llvm_profile_write_file();
	LOG("Done...\n");
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	int ret;

	assert(lkl_init(&lkl_host_ops) == 0);
	assert(lkl_start_kernel("mem=50M loglevel=8") == 0);

	assert(lkl_mount_fs("sysfs") == 0);
	assert(lkl_mount_fs("proc") == 0);

	ret = lkl_sys_mkdir("/dev", 0770);
	assert(ret == 0 || ret == -LKL_EEXIST);

	assert(lkl_sys_mount("devtmpfs", "/dev", "devtmpfs", 0, NULL) == 0);

	assert(_check_binder_version() == 0);

	__llvm_profile_initialize_file();
	atexit(flush_coverage);
	return 0;
}

void *ioctl_thread(void *arg)
{
	binder_ctx *ctx;

	lkl_set_task_flag(LKL_TASK_NEW_TGID);

	ctx = binder_open();
	if (!ctx)
		return NULL;

	lkl_random_sched_join();

	perform_ioctls(ctx, arg);
	binder_close(ctx);

	lkl_random_sched_leave();
	return NULL;
}

void *ioctl_ctx_manager_thread(void *arg)
{
	binder_ctx *ctx;

	ctx = binder_open();
	if (!ctx)
		return NULL;

	binder_ioctl_set_context_manager(ctx);

	lkl_random_sched_join();

	perform_ioctls(ctx, arg);
	binder_close(ctx);

	lkl_random_sched_leave();
	return NULL;
}

DEFINE_PROTO_FUZZER(const Session &session)
{
	size_t i;
	static int iter = 0;
	pthread_t tid[NUM_CLIENT];

	lkl_random_sched_init(3, session.scheduler_seed(),
			      session.scheduler_data().data(),
			      session.scheduler_data().size());

	pthread_create(&tid[0], NULL, ioctl_ctx_manager_thread,
		       (void *)&session.ioctls1());
	pthread_create(&tid[1], NULL, ioctl_thread, (void *)&session.ioctls2());
	pthread_create(&tid[2], NULL, ioctl_thread, (void *)&session.ioctls3());

	for (i = 0; i < NUM_CLIENT; i++) {
		pthread_join(tid[i], NULL);
	}

	lkl_random_sched_fini();

	iter++;
	if (iter > 1000) {
		flush_coverage();
		iter = 0;
	}
}
