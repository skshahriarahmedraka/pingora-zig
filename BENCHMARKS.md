# 🚀 pingora-zig Benchmark Results

This document showcases the performance benchmarks for pingora-zig, a high-performance
Zig implementation of Cloudflare's Pingora proxy framework components.

> **Generated:** 2026-01-26 22:52:40
>
> **Implementation:** pingora-zig
>
> **Default iterations:** 100,000

## 📊 Summary

### Comparison with pingora-rust

| Metric | Value |
|--------|-------|
| 🟢 Zig Wins | **15** |
| 🟡 Rust Wins | **11** |
| ⚪ Ties | **1** |
| Total Compared | 32 |

**🏆 Overall: pingora-zig wins 15/32 benchmarks!**

**Total benchmarks:** 55

**Legend:** 🟢 Zig faster | 🟡 Rust faster | ⚪ Tie (within 5%)

## 📈 Detailed Results

### 💾 Cache
_Cache key, lock, and predictor operations_

| Benchmark | Zig (ns/op) | Rust (ns/op) | Zig (ops/sec) | Ratio | |
|-----------|-------------|--------------|---------------|-------|--|
| key_create | 10 | 48 | 100.00M | 0.21x | 🟢 |
| lock_unlock | 8,379 | - | 119.34K | - | |
| predictor_check | 34 | - | 29.41M | - | |

### 🗜️ Compression
_Compression algorithm detection_

| Benchmark | Zig (ns/op) | Rust (ns/op) | Zig (ops/sec) | Ratio | |
|-----------|-------------|--------------|---------------|-------|--|
| parse_accept_encoding | 16 | 30 | 62.50M | 0.53x | 🟢 |
| check_compressible | 0 | 23 | 0 | N/A |  |
| ctx_negotiate | 0 | 0 | 0 | N/A |  |

### 🌐 HTTP
_HTTP request/response creation and headers_

| Benchmark | Zig (ns/op) | Rust (ns/op) | Zig (ops/sec) | Ratio | |
|-----------|-------------|--------------|---------------|-------|--|
| request_create | 7,144 | 121 | 139.98K | 59.04x | 🟡 |
| request_create_zerocopy | 31 | - | 32.26M | - | |
| header_append | 103 | 48 | 9.71M | 2.15x | 🟡 |
| header_lookup | 0 | 19 | 0 | N/A |  |

### 🚄 HTTP/2
_HTTP/2 HPACK and frame operations_

| Benchmark | Zig (ns/op) | Rust (ns/op) | Zig (ops/sec) | Ratio | |
|-----------|-------------|--------------|---------------|-------|--|
| parse_frame_header | 2 | - | 500.00M | - | |
| serialize_frame_header | 0 | - | 0 | - | |
| huffman_encoded_len | 0 | - | 0 | - | |
| huffman_encode | 64 | - | 15.62M | - | |
| settings_create | 0 | - | 0 | - | |
| hpack_encode_int | 0 | - | 0 | - | |
| huffman_decode | 17,940 | - | 55.74K | - | |

### 📄 HTTP Parser
_HTTP message parsing_

| Benchmark | Zig (ns/op) | Rust (ns/op) | Zig (ops/sec) | Ratio | |
|-----------|-------------|--------------|---------------|-------|--|
| parse_request | 243 | 149 | 4.12M | 1.63x | 🟡 |
| parse_response | 236 | 125 | 4.24M | 1.89x | 🟡 |
| parse_request_full | 243 | - | 4.12M | - | |

### 🔗 Ketama Consistent Hashing
_Consistent hashing for load distribution_

| Benchmark | Zig (ns/op) | Rust (ns/op) | Zig (ops/sec) | Ratio | |
|-----------|-------------|--------------|---------------|-------|--|
| create_continuum | 629,554 | 382,182 | 1.59K | 1.65x | 🟡 |
| node_hash | 72 | 100 | 13.89M | 0.72x | 🟢 |
| node_iter_3 | 70 | 100 | 14.29M | 0.70x | 🟢 |

### 📝 Linked List
_Doubly linked list operations_

| Benchmark | Zig (ns/op) | Rust (ns/op) | Zig (ops/sec) | Ratio | |
|-----------|-------------|--------------|---------------|-------|--|
| push_head | 9 | - | 111.11M | - | |
| pop_tail | 5 | - | 200.00M | - | |

### ⚖️ Load Balancer
_Backend management and health checks_

| Benchmark | Zig (ns/op) | Rust (ns/op) | Zig (ops/sec) | Ratio | |
|-----------|-------------|--------------|---------------|-------|--|
| backend_create | 14 | 20 | 71.43M | 0.70x | 🟢 |
| backend_hash | 8 | 16 | 125.00M | 0.50x | 🟢 |
| health_transition | 0 | - | 0 | - | |

### 🗄️ LRU Cache
_Least Recently Used cache operations_

| Benchmark | Zig (ns/op) | Rust (ns/op) | Zig (ops/sec) | Ratio | |
|-----------|-------------|--------------|---------------|-------|--|
| admit_new | 129 | 64 | 7.75M | 2.02x | 🟡 |
| admit_existing | 22 | 22 | 45.45M | 1.00x | ⚪ |
| peek | 11 | 13 | 90.91M | 0.85x | 🟢 |
| promote | 16 | 25 | 62.50M | 0.64x | 🟢 |

### 🧠 Memory Cache
_In-memory cache with TTL support_

| Benchmark | Zig (ns/op) | Rust (ns/op) | Zig (ops/sec) | Ratio | |
|-----------|-------------|--------------|---------------|-------|--|
| create | 32,776 | 280,206 | 30.51K | 0.12x | 🟢 |
| put_ttl | 205 | 466 | 4.88M | 0.44x | 🟢 |
| get_hit | 45 | 56 | 22.22M | 0.80x | 🟢 |
| get_miss | 13 | 22 | 76.92M | 0.59x | 🟢 |

### 🏊 Connection Pool
_Connection pooling operations_

| Benchmark | Zig (ns/op) | Rust (ns/op) | Zig (ops/sec) | Ratio | |
|-----------|-------------|--------------|---------------|-------|--|
| create_pool | 8 | 84 | 125.00M | 0.10x | 🟢 |
| put | 161 | 10 | 6.21M | 16.10x | 🟡 |
| get | 16 | 9 | 62.50M | 1.78x | 🟡 |
| meta_ops | 14 | 33 | 71.43M | 0.42x | 🟢 |

### 📡 QPACK
_HTTP/3 header compression_

| Benchmark | Zig (ns/op) | Rust (ns/op) | Zig (ops/sec) | Ratio | |
|-----------|-------------|--------------|---------------|-------|--|
| encode_integer | 0 | - | 0 | - | |
| decode_integer | 1 | - | 1.00B | - | |
| static_table_lookup | 1 | - | 1.00B | - | |
| static_table_find | 0 | - | 0 | - | |
| header_field_size | 0 | - | 0 | - | |

### ⏱️ Timeout
_Timer and timeout management_

| Benchmark | Zig (ns/op) | Rust (ns/op) | Zig (ops/sec) | Ratio | |
|-----------|-------------|--------------|---------------|-------|--|
| time_create | 0 | 0 | 0 | N/A |  |
| manager_create | 12 | 15 | 83.33M | 0.80x | 🟢 |
| time_compare | 0 | 0 | 0 | N/A |  |

### 📦 TinyUFO Cache
_TinyUFO cache with frequency-based eviction_

| Benchmark | Zig (ns/op) | Rust (ns/op) | Zig (ops/sec) | Ratio | |
|-----------|-------------|--------------|---------------|-------|--|
| put_eviction | 6,151 | 487 | 162.57K | 12.63x | 🟡 |
| get_hit | 52 | 32 | 19.23M | 1.62x | 🟡 |
| get_miss | 94 | 42 | 10.64M | 2.24x | 🟡 |

### 🔌 WebSocket
_WebSocket frame operations_

| Benchmark | Zig (ns/op) | Rust (ns/op) | Zig (ops/sec) | Ratio | |
|-----------|-------------|--------------|---------------|-------|--|
| parse_header | 2 | - | 500.00M | - | |
| build_header | 0 | - | 0 | - | |
| mask_256b | 57 | - | 17.54M | - | |
| validate_close_code | 0 | - | 0 | - | |

## 🌟 Performance Highlights

### Fastest Operations (by ops/sec)

| Rank | Benchmark | ops/sec |
|------|-----------|---------|
| 1 | qpack/decode_integer | 1.00B |
| 2 | qpack/static_table_lookup | 1.00B |
| 3 | websocket/parse_header | 500.00M |
| 4 | http2/parse_frame_header | 500.00M |
| 5 | linkedlist/pop_tail | 200.00M |

## 📝 Notes

- **ns/op**: Nanoseconds per operation (lower is better)
- **ops/sec**: Operations per second (higher is better)
- **Ratio**: Zig time / Rust time (< 1.0 means Zig is faster)
- Benchmarks run with `ReleaseFast` optimization
- Results may vary based on hardware and system load
