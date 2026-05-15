#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include "block_copyfail.h"
#include "block_copyfail.skel.h"

static volatile sig_atomic_t running = 1;

static void sig_handler(int sig)
{
	running = 0;
}

static int has_splice_to_socket(void)
{
	FILE *f = fopen("/proc/kallsyms", "r");
	if (!f)
		return 0;
	char line[256];
	int found = 0;
	while (fgets(line, sizeof(line), f)) {
		if (strstr(line, " splice_to_socket\n")) {
			found = 1;
			break;
		}
	}
	fclose(f);
	return found;
}

static const char *hook_name(__u32 hook)
{
	switch (hook) {
	case BLOCK_HOOK_CF1:   return "AF_ALG-AEAD";
	case BLOCK_HOOK_CF2:   return "ESP-UDP-splice";
	case BLOCK_HOOK_DF:    return "AF_RXRPC-AF_ALG";
	case BLOCK_HOOK_ENCAP: return "UDP_ENCAP";
	default:               return "unknown";
	}
}

static int handle_event(void *ctx, void *data, size_t len)
{
	struct block_event *evt = data;
	time_t now = time(NULL);
	struct tm *tm = localtime(&now);
	char ts[32];

	strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);
	fprintf(stderr, "block-copyfail: BLOCKED [%s] pid=%-8u comm=%.*s time=%s\n",
		hook_name(evt->hook), evt->pid, 16, evt->comm, ts);
	return 0;
}

int main(int argc, char **argv)
{
	struct block_copyfail_bpf *skel;
	struct ring_buffer *rb;
	int use_encap_fallback;

	skel = block_copyfail_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "block-copyfail: failed to load BPF program\n");
		return 1;
	}

	use_encap_fallback = !has_splice_to_socket();

	if (use_encap_fallback)
		fprintf(stderr, "block-copyfail: splice_to_socket not found — using UDP_ENCAP fallback\n");

	/* Attach programs individually so we can skip UDP_ENCAP on newer kernels */
	skel->links.block_copyfail = bpf_program__attach(skel->progs.block_copyfail);
	if (!skel->links.block_copyfail) {
		fprintf(stderr, "block-copyfail: failed to attach block_copyfail\n");
		goto err;
	}

	skel->links.block_dirty_frag = bpf_program__attach(skel->progs.block_dirty_frag);
	if (!skel->links.block_dirty_frag) {
		fprintf(stderr, "block-copyfail: failed to attach block_dirty_frag\n");
		goto err;
	}

	skel->links.block_copyfail2 = bpf_program__attach(skel->progs.block_copyfail2);
	if (!skel->links.block_copyfail2) {
		fprintf(stderr, "block-copyfail: failed to attach block_copyfail2\n");
		goto err;
	}

	if (use_encap_fallback) {
		skel->links.block_udp_encap = bpf_program__attach(skel->progs.block_udp_encap);
		if (!skel->links.block_udp_encap) {
			fprintf(stderr, "block-copyfail: failed to attach block_udp_encap\n");
			goto err;
		}
	}

	fprintf(stderr, "block-copyfail: blocker active — AF_ALG AEAD + UDP splice + AF_ALG + AF_RXRPC%s blocked\n",
		use_encap_fallback ? " + UDP_ENCAP" : "");

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
			      handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "block-copyfail: failed to create ring buffer\n");
		goto err;
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	while (running)
		ring_buffer__poll(rb, 250);

	fprintf(stderr, "block-copyfail: detaching blocker\n");
	ring_buffer__free(rb);
	block_copyfail_bpf__destroy(skel);
	return 0;

err:
	block_copyfail_bpf__destroy(skel);
	return 1;
}
