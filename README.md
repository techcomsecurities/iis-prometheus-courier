# iis-prometheus-courier
Microsoft IIS administration APIs export to prometheus.

More detail about IIS administration APIs at here https://docs.microsoft.com/en-us/iis-administration/api/monitoring
# How to run
```
go run main.go --user=your user name --pass=your pass word --addr=https://your ip:55539 --token=your token
```
```
./iis_prometheus_courier --user=your user name --pass=your pass word --addr=https://your ip:55539 --token=your token
```
# How to build
go build -o iis_prometheus_courier main.go
# How to connect to server
Enter to url: http://localhost:9121/metrics
# Use with prometheus
Edit your file prometheus.yml
```
- job_name: 'iis'
    metrics_path: '/metrics'
    static_configs:
     - targets: ['localhost:9121']
```     
U will got data look like this
```
# HELP go_gc_duration_seconds A summary of the pause duration of garbage collection cycles.
# TYPE go_gc_duration_seconds summary
go_gc_duration_seconds{quantile="0"} 0
go_gc_duration_seconds{quantile="0.25"} 0
go_gc_duration_seconds{quantile="0.5"} 0
go_gc_duration_seconds{quantile="0.75"} 0
go_gc_duration_seconds{quantile="1"} 0
go_gc_duration_seconds_sum 0
go_gc_duration_seconds_count 0
# HELP go_goroutines Number of goroutines that currently exist.
# TYPE go_goroutines gauge
go_goroutines 8
# HELP go_info Information about the Go environment.
# TYPE go_info gauge
go_info{version="go1.13.7"} 1
# HELP go_memstats_alloc_bytes Number of bytes allocated and still in use.
# TYPE go_memstats_alloc_bytes gauge
go_memstats_alloc_bytes 428080
# HELP go_memstats_alloc_bytes_total Total number of bytes allocated, even if freed.
# TYPE go_memstats_alloc_bytes_total counter
go_memstats_alloc_bytes_total 428080
# HELP go_memstats_buck_hash_sys_bytes Number of bytes used by the profiling bucket hash table.
# TYPE go_memstats_buck_hash_sys_bytes gauge
go_memstats_buck_hash_sys_bytes 2736
# HELP go_memstats_frees_total Total number of frees.
# TYPE go_memstats_frees_total counter
go_memstats_frees_total 88
# HELP go_memstats_gc_cpu_fraction The fraction of this program's available CPU time used by the GC since the program started.
# TYPE go_memstats_gc_cpu_fraction gauge
go_memstats_gc_cpu_fraction 0
# HELP go_memstats_gc_sys_bytes Number of bytes used for garbage collection system metadata.
# TYPE go_memstats_gc_sys_bytes gauge
go_memstats_gc_sys_bytes 2.240512e+06
# HELP go_memstats_heap_alloc_bytes Number of heap bytes allocated and still in use.
# TYPE go_memstats_heap_alloc_bytes gauge
go_memstats_heap_alloc_bytes 428080
# HELP go_memstats_heap_idle_bytes Number of heap bytes waiting to be used.
# TYPE go_memstats_heap_idle_bytes gauge
go_memstats_heap_idle_bytes 6.53312e+07
# HELP go_memstats_heap_inuse_bytes Number of heap bytes that are in use.
# TYPE go_memstats_heap_inuse_bytes gauge
go_memstats_heap_inuse_bytes 1.384448e+06
# HELP go_memstats_heap_objects Number of allocated objects.
# TYPE go_memstats_heap_objects gauge
go_memstats_heap_objects 1765
# HELP go_memstats_heap_released_bytes Number of heap bytes released to OS.
# TYPE go_memstats_heap_released_bytes gauge
go_memstats_heap_released_bytes 6.53312e+07
# HELP go_memstats_heap_sys_bytes Number of heap bytes obtained from system.
# TYPE go_memstats_heap_sys_bytes gauge
go_memstats_heap_sys_bytes 6.6715648e+07
# HELP go_memstats_last_gc_time_seconds Number of seconds since 1970 of last garbage collection.
# TYPE go_memstats_last_gc_time_seconds gauge
go_memstats_last_gc_time_seconds 0
# HELP go_memstats_lookups_total Total number of pointer lookups.
# TYPE go_memstats_lookups_total counter
go_memstats_lookups_total 0
# HELP go_memstats_mallocs_total Total number of mallocs.
# TYPE go_memstats_mallocs_total counter
go_memstats_mallocs_total 1853
# HELP go_memstats_mcache_inuse_bytes Number of bytes in use by mcache structures.
# TYPE go_memstats_mcache_inuse_bytes gauge
go_memstats_mcache_inuse_bytes 6944
# HELP go_memstats_mcache_sys_bytes Number of bytes used for mcache structures obtained from system.
# TYPE go_memstats_mcache_sys_bytes gauge
go_memstats_mcache_sys_bytes 16384
# HELP go_memstats_mspan_inuse_bytes Number of bytes in use by mspan structures.
# TYPE go_memstats_mspan_inuse_bytes gauge
go_memstats_mspan_inuse_bytes 19720
# HELP go_memstats_mspan_sys_bytes Number of bytes used for mspan structures obtained from system.
# TYPE go_memstats_mspan_sys_bytes gauge
go_memstats_mspan_sys_bytes 32768
# HELP go_memstats_next_gc_bytes Number of heap bytes when next garbage collection will take place.
# TYPE go_memstats_next_gc_bytes gauge
go_memstats_next_gc_bytes 4.473924e+06
# HELP go_memstats_other_sys_bytes Number of bytes used for other system allocations.
# TYPE go_memstats_other_sys_bytes gauge
go_memstats_other_sys_bytes 789840
# HELP go_memstats_stack_inuse_bytes Number of bytes in use by the stack allocator.
# TYPE go_memstats_stack_inuse_bytes gauge
go_memstats_stack_inuse_bytes 393216
# HELP go_memstats_stack_sys_bytes Number of bytes obtained from system for stack allocator.
# TYPE go_memstats_stack_sys_bytes gauge
go_memstats_stack_sys_bytes 393216
# HELP go_memstats_sys_bytes Number of bytes obtained from system.
# TYPE go_memstats_sys_bytes gauge
go_memstats_sys_bytes 7.0191104e+07
# HELP go_threads Number of OS threads created.
# TYPE go_threads gauge
go_threads 7
# HELP iis_RestAPIAPMcache_file_cache_count 
# TYPE iis_RestAPIAPMcache_file_cache_count gauge
iis_RestAPIAPMcache_file_cache_count{addr="https://10.7.2.4:55539",index="Cache"} 0
# HELP iis_RestAPIAPMcache_file_cache_hits 
# TYPE iis_RestAPIAPMcache_file_cache_hits gauge
iis_RestAPIAPMcache_file_cache_hits{addr="https://10.7.2.4:55539",index="Cache"} 0
# HELP iis_RestAPIAPMcache_file_cache_memory_usage 
# TYPE iis_RestAPIAPMcache_file_cache_memory_usage gauge
iis_RestAPIAPMcache_file_cache_memory_usage{addr="https://10.7.2.4:55539",index="Cache"} 0
# HELP iis_RestAPIAPMcache_file_cache_misses 
# TYPE iis_RestAPIAPMcache_file_cache_misses gauge
iis_RestAPIAPMcache_file_cache_misses{addr="https://10.7.2.4:55539",index="Cache"} 0
# HELP iis_RestAPIAPMcache_output_cache_count 
# TYPE iis_RestAPIAPMcache_output_cache_count gauge
iis_RestAPIAPMcache_output_cache_count{addr="https://10.7.2.4:55539",index="Cache"} 0
# HELP iis_RestAPIAPMcache_output_cache_hits 
# TYPE iis_RestAPIAPMcache_output_cache_hits gauge
iis_RestAPIAPMcache_output_cache_hits{addr="https://10.7.2.4:55539",index="Cache"} 0
# HELP iis_RestAPIAPMcache_output_cache_memory_usage 
# TYPE iis_RestAPIAPMcache_output_cache_memory_usage gauge
iis_RestAPIAPMcache_output_cache_memory_usage{addr="https://10.7.2.4:55539",index="Cache"} 0
# HELP iis_RestAPIAPMcache_output_cache_misses 
# TYPE iis_RestAPIAPMcache_output_cache_misses gauge
iis_RestAPIAPMcache_output_cache_misses{addr="https://10.7.2.4:55539",index="Cache"} 0
# HELP iis_RestAPIAPMcache_total_files_cached 
# TYPE iis_RestAPIAPMcache_total_files_cached gauge
iis_RestAPIAPMcache_total_files_cached{addr="https://10.7.2.4:55539",index="Cache"} 0
# HELP iis_RestAPIAPMcache_total_uris_cached 
# TYPE iis_RestAPIAPMcache_total_uris_cached gauge
iis_RestAPIAPMcache_total_uris_cached{addr="https://10.7.2.4:55539",index="Cache"} 0
# HELP iis_RestAPIAPMcache_uri_cache_count 
# TYPE iis_RestAPIAPMcache_uri_cache_count gauge
iis_RestAPIAPMcache_uri_cache_count{addr="https://10.7.2.4:55539",index="Cache"} 0
# HELP iis_RestAPIAPMcache_uri_cache_hits 
# TYPE iis_RestAPIAPMcache_uri_cache_hits gauge
iis_RestAPIAPMcache_uri_cache_hits{addr="https://10.7.2.4:55539",index="Cache"} 0
# HELP iis_RestAPIAPMcache_uri_cache_misses 
# TYPE iis_RestAPIAPMcache_uri_cache_misses gauge
iis_RestAPIAPMcache_uri_cache_misses{addr="https://10.7.2.4:55539",index="Cache"} 0
# HELP iis_RestAPIAPMcpu_percent_usage 
# TYPE iis_RestAPIAPMcpu_percent_usage gauge
iis_RestAPIAPMcpu_percent_usage{addr="https://10.7.2.4:55539",index="Cpu"} 0
# HELP iis_RestAPIAPMcpu_processes 
# TYPE iis_RestAPIAPMcpu_processes gauge
iis_RestAPIAPMcpu_processes{addr="https://10.7.2.4:55539",index="Cpu"} 0
# HELP iis_RestAPIAPMcpu_system_percent_usage 
# TYPE iis_RestAPIAPMcpu_system_percent_usage gauge
iis_RestAPIAPMcpu_system_percent_usage{addr="https://10.7.2.4:55539",index="Cpu"} 0
# HELP iis_RestAPIAPMcpu_threads 
# TYPE iis_RestAPIAPMcpu_threads gauge
iis_RestAPIAPMcpu_threads{addr="https://10.7.2.4:55539",index="Cpu"} 0
# HELP iis_RestAPIAPMdisk_io_read_operations_sec 
# TYPE iis_RestAPIAPMdisk_io_read_operations_sec gauge
iis_RestAPIAPMdisk_io_read_operations_sec{addr="https://10.7.2.4:55539",index="Disk"} 0
# HELP iis_RestAPIAPMdisk_io_write_operations_sec 
# TYPE iis_RestAPIAPMdisk_io_write_operations_sec gauge
iis_RestAPIAPMdisk_io_write_operations_sec{addr="https://10.7.2.4:55539",index="Disk"} 0
# HELP iis_RestAPIAPMdisk_page_faults_sec 
# TYPE iis_RestAPIAPMdisk_page_faults_sec gauge
iis_RestAPIAPMdisk_page_faults_sec{addr="https://10.7.2.4:55539",index="Disk"} 0
# HELP iis_RestAPIAPMmemory_handles 
# TYPE iis_RestAPIAPMmemory_handles gauge
iis_RestAPIAPMmemory_handles{addr="https://10.7.2.4:55539",index="Memory"} 0
# HELP iis_RestAPIAPMmemory_installed 
# TYPE iis_RestAPIAPMmemory_installed gauge
iis_RestAPIAPMmemory_installed{addr="https://10.7.2.4:55539",index="Memory"} 8.589463552e+09
# HELP iis_RestAPIAPMmemory_private_bytes 
# TYPE iis_RestAPIAPMmemory_private_bytes gauge
iis_RestAPIAPMmemory_private_bytes{addr="https://10.7.2.4:55539",index="Memory"} 0
# HELP iis_RestAPIAPMmemory_private_working_set 
# TYPE iis_RestAPIAPMmemory_private_working_set gauge
iis_RestAPIAPMmemory_private_working_set{addr="https://10.7.2.4:55539",index="Memory"} 0
# HELP iis_RestAPIAPMmemory_system_in_use 
# TYPE iis_RestAPIAPMmemory_system_in_use gauge
iis_RestAPIAPMmemory_system_in_use{addr="https://10.7.2.4:55539",index="Memory"} 4.61385728e+09
# HELP iis_RestAPIAPMrequests_active 
# TYPE iis_RestAPIAPMrequests_active gauge
iis_RestAPIAPMrequests_active{addr="https://10.7.2.4:55539",index="Requests"} 0
# HELP iis_RestAPIAPMrequests_per_sec 
# TYPE iis_RestAPIAPMrequests_per_sec gauge
iis_RestAPIAPMrequests_per_sec{addr="https://10.7.2.4:55539",index="Requests"} 0
# HELP iis_RestAPIAPMrequests_total 
# TYPE iis_RestAPIAPMrequests_total gauge
iis_RestAPIAPMrequests_total{addr="https://10.7.2.4:55539",index="Requests"} 0
# HELP iis_exporter_last_scrape_duration_seconds The last scrape duration.
# TYPE iis_exporter_last_scrape_duration_seconds gauge
iis_exporter_last_scrape_duration_seconds 18.3413557
# HELP process_cpu_seconds_total Total user and system CPU time spent in seconds.
# TYPE process_cpu_seconds_total counter
process_cpu_seconds_total 0
# HELP process_max_fds Maximum number of open file descriptors.
# TYPE process_max_fds gauge
process_max_fds 1.048576e+06
# HELP process_open_fds Number of open file descriptors.
# TYPE process_open_fds gauge
process_open_fds 8
# HELP process_resident_memory_bytes Resident memory size in bytes.
# TYPE process_resident_memory_bytes gauge
process_resident_memory_bytes 7.7824e+06
# HELP process_start_time_seconds Start time of the process since unix epoch in seconds.
# TYPE process_start_time_seconds gauge
process_start_time_seconds 1.5877375918e+09
# HELP process_virtual_memory_bytes Virtual memory size in bytes.
# TYPE process_virtual_memory_bytes gauge
process_virtual_memory_bytes 4.93092864e+08
# HELP process_virtual_memory_max_bytes Maximum amount of virtual memory available in bytes.
# TYPE process_virtual_memory_max_bytes gauge
process_virtual_memory_max_bytes -1
# HELP promhttp_metric_handler_requests_in_flight Current number of scrapes being served.
# TYPE promhttp_metric_handler_requests_in_flight gauge
promhttp_metric_handler_requests_in_flight 1
# HELP promhttp_metric_handler_requests_total Total number of scrapes by HTTP status code.
# TYPE promhttp_metric_handler_requests_total counter
promhttp_metric_handler_requests_total{code="200"} 0
promhttp_metric_handler_requests_total{code="500"} 0
promhttp_metric_handler_requests_total{code="503"} 0
```
![Screenshot](https://github.com/techcomsecurities/iis-prometheus-courier/blob/develop/Screenshot%20from%202020-04-27%2019-53-12.png)
Donate me, Pls send to Bitcoin address: 34AcbY4jKz7sPoi7WhM6pbvng6rF4fz5BK
