//! pingora-zig: Main library entry point
//!
//! A high-performance proxy framework written in pure Zig.
//! This is a port of Cloudflare's Pingora from Rust to Zig.
//!
//! Ported from: https://github.com/cloudflare/pingora

const std = @import("std");

// Level 0 modules (no internal dependencies)
pub const err = @import("error.zig");
pub const timeout = @import("timeout.zig");
pub const linked_list = @import("linked_list.zig");
pub const lru = @import("lru.zig");
pub const tinyufo = @import("tinyufo.zig");
pub const ketama = @import("ketama.zig");

// Re-export commonly used types
pub const Error = err.Error;
pub const ErrorType = err.ErrorType;
pub const ErrorSource = err.ErrorSource;

pub const Lru = lru.Lru;
pub const LruUnit = lru.LruUnit;
pub const LinkedList = linked_list.LinkedList;

pub const TinyUfo = tinyufo.TinyUfo;
pub const Continuum = ketama.Continuum;
pub const Bucket = ketama.Bucket;

// Level 1 modules (depend on Level 0)
pub const limits = @import("limits.zig");
pub const http = @import("http.zig");
pub const http_parser = @import("http_parser.zig");
pub const memory_cache = @import("memory_cache.zig");
pub const pool = @import("pool.zig");

// Re-export commonly used types from Level 1
pub const Estimator = limits.Estimator;
pub const Inflight = limits.Inflight;
pub const Rate = limits.Rate;

// HTTP types
pub const RequestHeader = http.RequestHeader;
pub const ResponseHeader = http.ResponseHeader;
pub const Headers = http.Headers;
pub const Method = http.Method;
pub const Version = http.Version;
pub const StatusCode = http.StatusCode;

// Memory cache types
pub const MemoryCache = memory_cache.MemoryCache;
pub const CacheStatus = memory_cache.CacheStatus;

// Pool types
pub const ConnectionPool = pool.ConnectionPool;
pub const ConnectionMeta = pool.ConnectionMeta;
pub const PoolNode = pool.PoolNode;

// HTTP Parser types
pub const parseRequest = http_parser.parseRequest;
pub const parseRequestFull = http_parser.parseRequestFull;
pub const parseResponse = http_parser.parseResponse;
pub const parseResponseFull = http_parser.parseResponseFull;
pub const ParsedRequest = http_parser.ParsedRequest;
pub const ParsedResponse = http_parser.ParsedResponse;
pub const HeaderRef = http_parser.HeaderRef;

// Integration tests
pub const integration_tests = @import("integration_tests.zig");

// Level 2 modules (depend on Level 0-1)
pub const header_serde = @import("header_serde.zig");
pub const runtime = @import("runtime.zig");
pub const tls = @import("tls.zig");

// Level 3 modules (Core networking)
pub const protocols = @import("protocols.zig");
pub const http_client = @import("http_client.zig");
pub const http_server = @import("http_server.zig");
pub const upstream = @import("upstream.zig");
pub const load_balancer = @import("load_balancer.zig");

// Header serde types
pub const HeaderSerde = header_serde.HeaderSerde;
pub const toWireFormat = header_serde.toWireFormat;
pub const requestToWireFormat = header_serde.requestToWireFormat;

// Runtime types
pub const Runtime = runtime.Runtime;
pub const TaskQueue = runtime.TaskQueue;
pub const Task = runtime.Task;

// TLS types
pub const TlsVersion = tls.TlsVersion;
pub const TlsServerConfig = tls.TlsServerConfig;
pub const TlsClientConfig = tls.TlsClientConfig;
pub const TlsInfo = tls.TlsInfo;
pub const TlsState = tls.TlsState;
pub const Certificate = tls.Certificate;
pub const PrivateKey = tls.PrivateKey;

// Protocol/Networking types
pub const TcpListener = protocols.TcpListener;
pub const TcpStream = protocols.TcpStream;
pub const TcpConnector = protocols.TcpConnector;
pub const TcpOptions = protocols.TcpOptions;
pub const ConnectionInfo = protocols.ConnectionInfo;
pub const PeerAddress = protocols.PeerAddress;

// HTTP Client types
pub const HttpClient = http_client.HttpClient;
pub const HttpSession = http_client.HttpSession;
pub const HttpResponse = http_client.HttpResponse;
pub const HttpClientConfig = http_client.HttpClientConfig;

// HTTP Server types
pub const HttpServer = http_server.HttpServer;
pub const HttpServerSession = http_server.HttpServerSession;
pub const HttpRequest = http_server.HttpRequest;
pub const HttpServerConfig = http_server.HttpServerConfig;

// Upstream types
pub const Peer = upstream.Peer;
pub const PeerStats = upstream.PeerStats;
pub const PeerOptions = upstream.PeerOptions;
pub const UpstreamGroup = upstream.UpstreamGroup;
pub const HealthStatus = upstream.HealthStatus;
pub const HealthCheckConfig = upstream.HealthCheckConfig;

// Load Balancer types
pub const LoadBalancer = load_balancer.LoadBalancer;
pub const RoundRobin = load_balancer.RoundRobin;
pub const WeightedRoundRobin = load_balancer.WeightedRoundRobin;
pub const LeastConnections = load_balancer.LeastConnections;
pub const ConsistentHash = load_balancer.ConsistentHash;
pub const Algorithm = load_balancer.Algorithm;

// Level 4 modules (depend on Level 0-3)
pub const cache = @import("cache.zig");
pub const compression = @import("compression.zig");

// Cache types
pub const HttpCache = cache.HttpCache;
pub const HttpCacheConfig = cache.HttpCacheConfig;
pub const CacheControl = cache.CacheControl;
pub const CacheKey = cache.CacheKey;
pub const CacheMeta = cache.CacheMeta;
pub const CachedResponse = cache.CachedResponse;
pub const CacheLookupResult = cache.CacheLookupResult;

// Compression types
pub const CompressionAlgorithm = compression.Algorithm;
pub const CompressionLevel = compression.CompressionLevel;
pub const CompressionStats = compression.CompressionStats;
pub const ResponseCompressionCtx = compression.ResponseCompressionCtx;
pub const ResponseDecompressionCtx = compression.ResponseDecompressionCtx;
pub const isCompressibleContentType = compression.isCompressibleContentType;
pub const DEFAULT_COMPRESSIBLE_TYPES = compression.DEFAULT_COMPRESSIBLE_TYPES;
pub const DEFAULT_MIN_SIZE = compression.DEFAULT_MIN_SIZE;

// Level 5 modules (top level) - Proxy Framework
pub const proxy = @import("proxy.zig");

// HTTP/2 support
pub const http2 = @import("http2.zig");

// WebSocket support
pub const websocket = @import("websocket.zig");

// QUIC and HTTP/3 support
pub const quic = @import("quic.zig");
pub const http3 = @import("http3.zig");
pub const quiche_ffi = @import("quiche_ffi.zig");

// Proxy types
pub const HttpProxy = proxy.HttpProxy;
pub const HttpProxyConfig = proxy.HttpProxyConfig;
pub const ProxyHttp = proxy.ProxyHttp;
pub const Session = proxy.Session;
pub const SessionTiming = proxy.SessionTiming;
pub const FilterResult = proxy.FilterResult;
pub const ProxyError = proxy.ProxyError;
pub const proxyHttpFrom = proxy.proxyHttpFrom;

// Pre-built proxy implementations
pub const LoadBalancerProxy = proxy.LoadBalancerProxy;
pub const ReverseProxy = proxy.ReverseProxy;

test {
    // Run all tests from submodules
    std.testing.refAllDecls(@This());
}
