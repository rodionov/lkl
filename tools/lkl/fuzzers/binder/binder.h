#ifndef BINDER_H_
#define BINDER_H_

extern "C" {
#define new extern_new
#include <lkl.h>
#include <lkl_host.h>
#include <lkl/linux/android/binder.h>
#undef new
}

#include <cstdint>
#include <vector>
#include <queue>

#define RANDOM_SIZE_RANGE 8
/*
 * Binder context
 * @fd - file description to a binder device
 * @epoll_fd - epoll for the binder fd
 * @map_ptr - pointer to mmaped memory
 * @map_size - mmapped memory size
 * @task - a pointer to the task_struct that opened the binder device
 * @buffers - buffers of incoming transactions
 */
typedef struct {
	int fd;
	int epoll_fd;
	void *map_ptr;
	size_t map_size;
	void *task;
	std::queue<lkl_binder_uintptr_t> buffers;
} binder_ctx;

struct binder_object {
	union {
		struct lkl_binder_object_header hdr;
		struct lkl_flat_binder_object fbo;
		struct lkl_binder_fd_object fdo;
		struct lkl_binder_buffer_object bbo;
		struct lkl_binder_fd_array_object fdao;
	};
};

/*
 * Binder open, close
 */
binder_ctx *binder_open();
void binder_close(binder_ctx *ctx);

/*
 * IOCTL
 */
int binder_ioctl_set_context_manager(binder_ctx *ctx);
int binder_ioctl_write(binder_ctx *ctx, void *buffer, size_t size);
int binder_ioctl_read(binder_ctx *ctx, void *buffer, size_t size,
		      lkl_binder_size_t *read_consumed);
int binder_ioctl_thread_exit(binder_ctx *ctx);
int binder_ioctl_check_version(binder_ctx *ctx);
int binder_ioctl_get_node_debug_info(binder_ctx *ctx, lkl_binder_uintptr_t ptr);
int binder_ioctl_get_node_info_for_ref(binder_ctx *ctx, uint32_t handle);
int binder_ioctl_enable_oneway_spam_detection(binder_ctx *ctx, bool e);
int binder_ioctl_get_extended_error(binder_ctx *ctx, uint32_t handle);
typedef struct {
	uint8_t data0[256];
	uint8_t *data;
	size_t data_avail;
	lkl_binder_size_t offs0[256];
	lkl_binder_size_t *offs;
	size_t offs_avail;
	uint8_t extra_data0[256];
	uint8_t *extra_data;
	size_t extra_data_avail;
	int fd;
} txnout_t;
void txnout_init(txnout_t *txnout);
void *txnout_alloc(txnout_t *txnout, size_t size);
void *txnout_extra_buf_alloc(txnout_t *txnout, size_t size);
typedef struct {
	uint8_t *data0;
	uint8_t *data;
	size_t data_avail;
	std::vector<txnout_t *> txnouts;
} bwr_buf_t;
void bwr_buf_init(bwr_buf_t *bb, size_t size);
void bwr_buf_init_with_data(bwr_buf_t *bb, uint8_t *ptr, size_t size);
void bwr_buf_fini(bwr_buf_t *bb);
struct lkl_binder_transaction_data *bwr_buf_alloc_transaction(bwr_buf_t *bb,
							      bool reply);
struct lkl_binder_transaction_data_sg *
bwr_buf_alloc_transaction_sg(bwr_buf_t *bb, bool reply);
void bwr_buf_put_bc(bwr_buf_t *bb, uint32_t bc);
void bwr_buf_put_binder_req(bwr_buf_t *bb, lkl_binder_uintptr_t binder_ptr,
			    bool cookie, uint32_t bc);
void bwr_buf_put_handle_req(bwr_buf_t *bb, uint32_t handle, uint32_t bc);
void bwr_buf_put_free_buffer(bwr_buf_t *bb, lkl_binder_uintptr_t buffer_addr);
void bwr_buf_put_death_notif_req(bwr_buf_t *bb, lkl_binder_uintptr_t binder_ptr,
				 bool cookie, uint32_t bc);
void bwr_buf_put_dead_binder_done(bwr_buf_t *bb, bool cookie);
typedef struct {
	uint8_t *data0;
	uint8_t *data;
	size_t data_avail;
} txnin_t;
void txnin_init(txnin_t *txnin, struct binder_transaction_data *tr);
int binder_recv(binder_ctx *ctx, size_t size);
int binder_send(binder_ctx *ctx, bwr_buf_t *bb);
#endif // BINDER_H_