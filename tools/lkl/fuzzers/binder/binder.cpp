#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>

#include "binder.h"

#define ERR(fmt, ...) printf("ERROR: " fmt "\n", ##__VA_ARGS__)

#define BINDER_DEVICE "/dev/binder"
#define BINDER_VM_SIZE 1 * 1024 * 1024

#define PAD_SIZE_UNSAFE(s) (((s) + 3) & ~3UL)

binder_ctx *binder_open()
{
	binder_ctx *ctx;

	ctx = new binder_ctx;
	if (!ctx)
		return NULL;

	ctx->fd =
		lkl_sys_open(BINDER_DEVICE, O_RDWR | O_CLOEXEC | O_NONBLOCK, 0);
	if (ctx->fd == -1) {
		ERR("Failed to open binder device");
		goto err_open;
	}

	ctx->epoll_fd = -1;
	ctx->map_size = BINDER_VM_SIZE;
	ctx->map_ptr = lkl_sys_mmap(NULL, BINDER_VM_SIZE, PROT_READ,
				    MAP_PRIVATE, ctx->fd, 0);
	if (ctx->map_ptr == MAP_FAILED) {
		ERR("Failed to mmap binder device");
		goto err_mmap;
	}

	return ctx;
err_mmap:
	lkl_sys_close(ctx->fd);
err_open:
	delete ctx;
	return NULL;
}

void binder_close(binder_ctx *ctx)
{
	if (ctx) {
		lkl_sys_munmap((unsigned long)ctx->map_ptr, ctx->map_size);
		lkl_sys_close(ctx->fd);
		if (ctx->epoll_fd != -1) {
			lkl_sys_close(ctx->epoll_fd);
		}
		delete ctx;
	}
}

int binder_ioctl_set_context_manager(binder_ctx *ctx)
{
	int ret;

	ret = lkl_sys_ioctl(ctx->fd, LKL_BINDER_SET_CONTEXT_MGR, 0);
	if (ret < 0) {
		ERR("Failed to set context manager");
	}
	return ret;
}

int binder_ioctl_write(binder_ctx *ctx, void *buffer, size_t size)
{
	int ret;
	struct lkl_binder_write_read bwr = {
		.write_size = size,
		.write_consumed = 0,
		.write_buffer = (lkl_binder_uintptr_t)buffer
	};

	ret = lkl_sys_ioctl(ctx->fd, LKL_BINDER_WRITE_READ,
			    (unsigned long)&bwr);
	if (ret < 0)
		return ret;

	return bwr.write_consumed;
}

int binder_ioctl_read(binder_ctx *ctx, void *buffer, size_t size,
		      lkl_binder_size_t *read_consumed)
{
	int ret;

	struct lkl_binder_write_read bwr = {
		.read_size = size,
		.read_consumed = 0,
		.read_buffer = (lkl_binder_uintptr_t)buffer
	};

	ret = lkl_sys_ioctl(ctx->fd, LKL_BINDER_WRITE_READ,
			    (unsigned long)&bwr);
	if (ret == 0) {
		*read_consumed = bwr.read_consumed;
	}

	return ret;
}

int binder_ioctl_thread_exit(binder_ctx *ctx)
{
	int ret;

	ret = lkl_sys_ioctl(ctx->fd, LKL_BINDER_THREAD_EXIT, 0);
	if (ret < 0) {
		ERR("Failed to perform thread exit");
	}
	return ret;
}

int binder_ioctl_check_version(binder_ctx *ctx)
{
	int ret;
	struct lkl_binder_version version = { 0 };

	ret = lkl_sys_ioctl(ctx->fd, LKL_BINDER_VERSION,
			    (unsigned long)&version);
	if (ret < 0) {
		return ret;
	} else if (version.protocol_version !=
		   LKL_BINDER_CURRENT_PROTOCOL_VERSION) {
		ERR("Binder version does not match: %u",
		    version.protocol_version);
		return -1;
	}

	return 0;
}

int binder_ioctl_get_node_debug_info(binder_ctx *ctx, lkl_binder_uintptr_t ptr)
{
	struct lkl_binder_node_debug_info info = { .ptr = ptr };

	return lkl_sys_ioctl(ctx->fd, LKL_BINDER_GET_NODE_DEBUG_INFO,
			     (unsigned long)&info);
}

int binder_ioctl_get_node_info_for_ref(binder_ctx *ctx, uint32_t handle)
{
	struct lkl_binder_node_info_for_ref info = { .handle = handle };

	return lkl_sys_ioctl(ctx->fd, LKL_BINDER_GET_NODE_INFO_FOR_REF,
			     (unsigned long)&info);
}

int binder_ioctl_enable_oneway_spam_detection(binder_ctx *ctx, bool e)
{
	uint32_t enable = e;

	return lkl_sys_ioctl(ctx->fd, LKL_BINDER_ENABLE_ONEWAY_SPAM_DETECTION,
			     (unsigned long)&enable);
}

void txnout_init(txnout_t *txnout)
{
	txnout->data = txnout->data0;
	txnout->data_avail = sizeof(txnout->data0) - RANDOM_SIZE_RANGE;
	txnout->offs = txnout->offs0;
	txnout->offs_avail =
		(sizeof(txnout->offs0) - 8) / sizeof(lkl_binder_size_t);
	txnout->extra_data = txnout->extra_data0;
	txnout->extra_data_avail =
		sizeof(txnout->extra_data0) - RANDOM_SIZE_RANGE;
	txnout->fd = -1;
}

void *txnout_alloc(txnout_t *txnout, size_t size)
{
	void *ptr;
	if (size > txnout->data_avail || !txnout->offs_avail)
		return NULL;
	ptr = txnout->data;
	txnout->data += size;
	txnout->data_avail -= size;
	txnout->offs_avail--;
	*txnout->offs++ = ((uint8_t *)ptr) - ((uint8_t *)txnout->data0);
	return ptr;
}

void *txnout_extra_buf_alloc(txnout_t *txnout, size_t size)
{
	void *ptr;
	if (size > txnout->extra_data_avail)
		return NULL;
	ptr = txnout->extra_data;
	txnout->extra_data += size;
	txnout->extra_data_avail -= size;
	return ptr;
}

void bwr_buf_init(bwr_buf_t *bb, size_t size)
{
	bb->data0 = (uint8_t *)malloc(size);
	bb->data = bb->data0;
	bb->data_avail = size;
}

void bwr_buf_init_with_data(bwr_buf_t *bb, uint8_t *ptr, size_t size)
{
	bb->data = ptr;
	bb->data_avail = size;
}

static void _bwr_buf_clear_txnouts(bwr_buf_t *bb)
{
	txnout_t *txnout;
	while (!bb->txnouts.empty()) {
		txnout = bb->txnouts.back();
		bb->txnouts.pop_back();
		if (txnout->fd != -1) {
			lkl_sys_close(txnout->fd);
		}
		free(txnout);
	}
}

void bwr_buf_fini(bwr_buf_t *bb)
{
	_bwr_buf_clear_txnouts(bb);
	free(bb->data0);
}

void *bwr_buf_alloc(bwr_buf_t *bb, size_t size)
{
	void *ptr;
	if (size > bb->data_avail)
		return NULL;
	ptr = bb->data;
	bb->data += size;
	bb->data_avail -= size;
	return ptr;
}

void bwr_buf_put_uint32(bwr_buf_t *bb, uint32_t value)
{
	uint32_t *ptr = (uint32_t *)bwr_buf_alloc(bb, sizeof(value));
	if (ptr)
		*ptr = value;
}

void bwr_buf_put_uintptr(bwr_buf_t *bb, lkl_binder_uintptr_t value)
{
	lkl_binder_uintptr_t *ptr =
		(lkl_binder_uintptr_t *)bwr_buf_alloc(bb, sizeof(value));
	if (ptr)
		*ptr = value;
}

void bwr_buf_put_bc(bwr_buf_t *bb, uint32_t bc)
{
	bwr_buf_put_uint32(bb, bc);
}

void bwr_buf_put_binder_req(bwr_buf_t *bb, lkl_binder_uintptr_t binder_ptr,
			    bool cookie, uint32_t bc)
{
	if (bb->data_avail < (sizeof(uint32_t) + sizeof(lkl_binder_uintptr_t) +
			      sizeof(lkl_binder_uintptr_t))) {
		return;
	}
	bwr_buf_put_uint32(bb, bc);
	bwr_buf_put_uintptr(bb, binder_ptr);
	bwr_buf_put_uintptr(bb, cookie);
}

void bwr_buf_put_handle_req(bwr_buf_t *bb, uint32_t handle, uint32_t bc)
{
	if (bb->data_avail < (sizeof(uint32_t) + sizeof(uint32_t))) {
		return;
	}
	bwr_buf_put_uint32(bb, bc);
	bwr_buf_put_uint32(bb, handle);
}

struct lkl_binder_transaction_data *bwr_buf_alloc_transaction(bwr_buf_t *bb,
							      bool reply)
{
	struct lkl_binder_transaction_data *tr_data;

	if (bb->data_avail <
	    (sizeof(uint32_t) + sizeof(struct lkl_binder_transaction_data))) {
		return NULL;
	}
	bwr_buf_put_uint32(bb, reply ? LKL_BC_REPLY : LKL_BC_TRANSACTION);
	tr_data = (struct lkl_binder_transaction_data *)bwr_buf_alloc(
		bb, sizeof(*tr_data));
	return tr_data;
}

struct lkl_binder_transaction_data_sg *
bwr_buf_alloc_transaction_sg(bwr_buf_t *bb, bool reply)
{
	struct lkl_binder_transaction_data_sg *tr_data_sg;

	if (bb->data_avail < (sizeof(uint32_t) +
			      sizeof(struct lkl_binder_transaction_data_sg))) {
		return NULL;
	}
	bwr_buf_put_uint32(bb, reply ? LKL_BC_REPLY_SG : LKL_BC_TRANSACTION_SG);
	tr_data_sg = (struct lkl_binder_transaction_data_sg *)bwr_buf_alloc(
		bb, sizeof(*tr_data_sg));
	return tr_data_sg;
}

void bwr_buf_put_free_buffer(bwr_buf_t *bb, lkl_binder_uintptr_t buffer_addr)
{
	if (bb->data_avail <
	    (sizeof(uint32_t) + sizeof(lkl_binder_uintptr_t))) {
		return;
	}
	bwr_buf_put_uint32(bb, LKL_BC_FREE_BUFFER);
	bwr_buf_put_uintptr(bb, buffer_addr);
}

void bwr_buf_put_death_notif_req(bwr_buf_t *bb, lkl_binder_uintptr_t binder_ptr,
				 bool cookie, uint32_t bc)
{
	if (bb->data_avail <
	    (sizeof(uint32_t) + sizeof(lkl_binder_uintptr_t))) {
		return;
	}
	bwr_buf_put_uint32(bb, bc);
	bwr_buf_put_uint32(bb, binder_ptr);
	bwr_buf_put_uintptr(bb, cookie);
}

void bwr_buf_put_dead_binder_done(bwr_buf_t *bb, bool cookie)
{
	if (bb->data_avail <
	    (sizeof(uint32_t) + sizeof(lkl_binder_uintptr_t))) {
		return;
	}
	bwr_buf_put_uint32(bb, LKL_BC_DEAD_BINDER_DONE);
	bwr_buf_put_uintptr(bb, cookie);
}

static void *_bwr_buf_pop(bwr_buf_t *bb, size_t size)
{
	void *ptr;
	if (size > bb->data_avail)
		return NULL;
	ptr = bb->data;
	bb->data += size;
	bb->data_avail -= size;
	return ptr;
}

static uint32_t _bwr_buf_pop_uint32(bwr_buf_t *bb)
{
	uint32_t *value;
	value = (uint32_t *)_bwr_buf_pop(bb, sizeof(uint32_t));
	if (!value) {
		return 0;
	}
	return *value;
}

void txnin_init(txnin_t *txnin, struct lkl_binder_transaction_data *tr_data)
{
	txnin->data0 = txnin->data = (uint8_t *)tr_data->data.ptr.buffer;
	txnin->data_avail = tr_data->data_size;
}

static void _binder_execute_cmds(binder_ctx *ctx, bwr_buf_t *bb)
{
	txnin_t txnin;
	uint32_t cmd;
	void *cmd_data;

	while (bb->data_avail > 0) {
		cmd = _bwr_buf_pop_uint32(bb);
		cmd_data = _bwr_buf_pop(bb, _LKL_IOC_SIZE(cmd));
		switch (cmd) {
		case LKL_BR_ACQUIRE:
		case LKL_BR_INCREFS: {
			bwr_buf_t bb_out;
			struct lkl_binder_ptr_cookie *bpc =
				(struct lkl_binder_ptr_cookie *)cmd_data;
			bwr_buf_init(&bb_out, 256);
			bwr_buf_put_uint32(&bb_out,
					   cmd == LKL_BR_ACQUIRE ?
						   LKL_BC_ACQUIRE_DONE :
						   LKL_BC_INCREFS_DONE);
			bwr_buf_put_uintptr(&bb_out, bpc->ptr);
			bwr_buf_put_uintptr(&bb_out, bpc->cookie);
			binder_send(ctx, &bb_out);
			bwr_buf_fini(&bb_out);
		} break;
		case LKL_BR_DEAD_BINDER: {
			bwr_buf_t bb_out;
			lkl_binder_uintptr_t cookie =
				*(lkl_binder_uintptr_t *)cmd_data;
			bwr_buf_init(&bb_out, 256);
			bwr_buf_put_uint32(&bb_out, LKL_BC_DEAD_BINDER_DONE);
			bwr_buf_put_uintptr(&bb_out, cookie);
			binder_send(ctx, &bb_out);
			bwr_buf_fini(&bb_out);
		} break;
		case LKL_BR_TRANSACTION:
		case LKL_BR_REPLY:
			txnin_init(
				&txnin,
				(struct lkl_binder_transaction_data *)cmd_data);
			ctx->buffers.push((lkl_binder_uintptr_t)txnin.data0);
			break;
		default:
			break;
		}
	}
}

int binder_recv(binder_ctx *ctx, size_t size)
{
	int ret;
	bwr_buf_t bb;
	uint8_t read_buf[size];
	lkl_binder_size_t read_consumed;

	ret = binder_ioctl_read(ctx, read_buf, sizeof(read_buf),
				&read_consumed);
	if (ret)
		return ret;
	bwr_buf_init_with_data(&bb, read_buf, read_consumed);
	_binder_execute_cmds(ctx, &bb);

	return 0;
}

int binder_send(binder_ctx *ctx, bwr_buf_t *bb)
{
	return binder_ioctl_write(ctx, bb->data0,
				  PAD_SIZE_UNSAFE(bb->data - bb->data0));
}
