#ifndef _PXD_CONFIG_H_
#define _PXD_CONFIG_H_

// Configuration parameters
// Summary of test results:
// Multiple threads are needed to saturate random reads
// Single threaded write path with sync writes offer better performance, or have
// negligible loss when compared to async writes. Sync writes are good for data
// integrity as well. If available exported sync interface, use it.
// So the above will be the default configuration.
//
// Also generally block request handling has two interfaces, one fetching
// directly each BIO, the other does collect requests in a queue and does
// batch push them through elevator merging... we are directly using the
// original block io interface, did not find much performance help using
// the request Queue interface... So USE_REQUEST_QUEUE shall remain disabled
// as default.
//

#define MAX_THREADS (nr_cpu_ids)
#define STATIC

#endif /* _PXD_CONFIG_H_ */
