# Phase Chart

A visual reference for the Pingora-Zig request processing phases.

## Complete Phase Flow

```
                          ┌─────────────────────────────────────┐
                          │         CLIENT REQUEST              │
                          └──────────────┬──────────────────────┘
                                         │
                                         ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                           REQUEST FILTER PHASE                              │
│                                                                             │
│  • Validate request                                                         │
│  • Add/modify headers                                                       │
│  • Set up context                                                           │
│  • Rate limiting                                                            │
│                                                                             │
│  Returns: continue_processing | reject | respond                            │
└────────────────────────────────────────┬───────────────────────────────────┘
                                         │
                          ┌──────────────┴──────────────┐
                          │      CACHE ENABLED?         │
                          └──────────────┬──────────────┘
                                    YES  │  NO
                          ┌──────────────┴──────────────┐
                          │                             │
                          ▼                             │
┌─────────────────────────────────────────┐            │
│         CACHE LOOKUP PHASE              │            │
│                                         │            │
│  • Check cache for response             │            │
│  • Validate cache freshness             │            │
│  • Handle conditional requests          │            │
└────────────────┬────────────────────────┘            │
                 │                                     │
          ┌──────┴──────┐                              │
          │  CACHE HIT? │                              │
          └──────┬──────┘                              │
            YES  │  NO                                 │
          ┌──────┴──────┐                              │
          │             │                              │
          ▼             └──────────────┬───────────────┘
┌──────────────────┐                   │
│  RETURN CACHED   │                   │
│    RESPONSE      │                   │
└────────┬─────────┘                   │
         │                             │
         │                             ▼
         │         ┌────────────────────────────────────────────────────────┐
         │         │              UPSTREAM PEER PHASE                       │
         │         │                                                        │
         │         │  • Select upstream server                              │
         │         │  • Load balancing decision                             │
         │         │  • Service discovery                                   │
         │         │                                                        │
         │         │  Returns: Peer | null (no backend available)           │
         │         └───────────────────────┬────────────────────────────────┘
         │                                 │
         │                                 ▼
         │         ┌────────────────────────────────────────────────────────┐
         │         │         UPSTREAM REQUEST FILTER PHASE                  │
         │         │                                                        │
         │         │  • Modify request for backend                          │
         │         │  • Add authentication                                  │
         │         │  • Add tracing headers                                 │
         │         │                                                        │
         │         │  Returns: continue_processing | reject                 │
         │         └───────────────────────┬────────────────────────────────┘
         │                                 │
         │                                 ▼
         │         ┌────────────────────────────────────────────────────────┐
         │         │            CONNECT TO UPSTREAM                         │
         │         │                                                        │
         │         │  • Get connection from pool                            │
         │         │  • Or create new connection                            │
         │         │  • TLS handshake if needed                             │
         │         └───────────────────────┬────────────────────────────────┘
         │                                 │
         │                          ┌──────┴──────┐
         │                          │  SUCCESS?   │
         │                          └──────┬──────┘
         │                            YES  │  NO
         │                          ┌──────┴──────┐
         │                          │             │
         │                          │             ▼
         │                          │    ┌────────────────────┐
         │                          │    │ FAIL TO CONNECT    │
         │                          │    │                    │
         │                          │    │ • Mark unhealthy   │
         │                          │    │ • Retry?           │
         │                          │    └────────┬───────────┘
         │                          │             │
         │                          │      ┌──────┴──────┐
         │                          │      │   RETRY?    │
         │                          │      └──────┬──────┘
         │                          │        YES  │  NO
         │                          │      ┌──────┴──────┐
         │                          │      │             │
         │                          │      │             ▼
         │                          │      │     ┌──────────────┐
         │                          │      │     │ RETURN ERROR │
         │                          │      │     │   RESPONSE   │
         │                          │      │     └──────┬───────┘
         │                          │      │            │
         │                          │      └─────►──────┤
         │                          │                   │
         │                          ▼                   │
         │         ┌────────────────────────────────────┴───────────────────┐
         │         │          SEND REQUEST TO UPSTREAM                      │
         │         │                                                        │
         │         │  • Send request headers                                │
         │         │  • Send request body                                   │
         │         │  • Wait for response                                   │
         │         └───────────────────────┬────────────────────────────────┘
         │                                 │
         │                                 ▼
         │         ┌────────────────────────────────────────────────────────┐
         │         │         RECEIVE UPSTREAM RESPONSE                      │
         │         │                                                        │
         │         │  • Parse response headers                              │
         │         │  • Stream response body                                │
         │         └───────────────────────┬────────────────────────────────┘
         │                                 │
         │                                 ▼
         │         ┌────────────────────────────────────────────────────────┐
         │         │            RESPONSE FILTER PHASE                       │
         │         │                                                        │
         │         │  • Add/modify response headers                         │
         │         │  • Add security headers                                │
         │         │  • Transform response body                             │
         │         │  • Decide caching                                      │
         │         │                                                        │
         │         │  Returns: continue_processing | respond                │
         │         └───────────────────────┬────────────────────────────────┘
         │                                 │
         │                          ┌──────┴──────┐
         │                          │ CACHEABLE?  │
         │                          └──────┬──────┘
         │                            YES  │  NO
         │                          ┌──────┴──────┐
         │                          │             │
         │                          ▼             │
         │         ┌─────────────────────────────┐│
         │         │      CACHE STORE PHASE      ││
         │         │                             ││
         │         │  • Store response in cache  ││
         │         │  • Set TTL                  ││
         │         │  • Update cache metadata    ││
         │         └────────────────┬────────────┘│
         │                          │             │
         │                          └──────┬──────┘
         │                                 │
         └─────────────────────────────────┤
                                           │
                                           ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                        SEND RESPONSE TO CLIENT                             │
│                                                                            │
│  • Send response headers                                                   │
│  • Send response body                                                      │
└────────────────────────────────────────┬───────────────────────────────────┘
                                         │
                                         ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                           LOGGING PHASE                                    │
│                                                                            │
│  • Log request/response                                                    │
│  • Update metrics                                                          │
│  • Clean up resources                                                      │
│  • Return connection to pool                                               │
└────────────────────────────────────────────────────────────────────────────┘
```

## Phase Summary Table

| Phase | Purpose | Can Reject? | Can Respond? |
|-------|---------|-------------|--------------|
| request_filter | Validate and modify incoming request | ✅ | ✅ |
| cache_lookup | Check cache for response | ❌ | ✅ (cached) |
| upstream_peer | Select backend server | ✅ (no peer) | ❌ |
| upstream_request_filter | Modify request to backend | ✅ | ❌ |
| connect | Establish upstream connection | ✅ (retry) | ❌ |
| response_filter | Modify response from backend | ❌ | ✅ |
| cache_store | Store cacheable responses | ❌ | ❌ |
| logging | Log and cleanup | ❌ | ❌ |

## Retry Flow

```
┌─────────────────────────────────────────────────────────────┐
│                      RETRY LOGIC                            │
│                                                             │
│  1. Connection fails or error during request                │
│  2. Check retry_count < max_retries                         │
│  3. If retriable:                                           │
│     • Increment retry_count                                 │
│     • Mark current peer unhealthy (optional)                │
│     • Go back to upstream_peer phase                        │
│     • Select different peer                                 │
│  4. If not retriable:                                       │
│     • Return error response to client                       │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Error Handling Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    ERROR HANDLING                           │
│                                                             │
│  Any phase can encounter an error:                          │
│                                                             │
│  • Connection errors → fail_to_connect callback             │
│  • Upstream errors → error_while_proxying callback          │
│  • Parse errors → Return 400 Bad Request                    │
│  • Internal errors → Return 500 Internal Server Error       │
│                                                             │
│  Error callbacks can:                                       │
│  • Log the error                                            │
│  • Update metrics                                           │
│  • Decide to retry                                          │
│  • Return custom error response                             │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```
