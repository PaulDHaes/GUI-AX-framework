# Fleet Data Caching

## Problem

Previously, every dashboard load/refresh triggered `axiom-ls --json`, which queries AWS EC2. This was:

- **Slow** (AWS API calls take 2-5+ seconds)
- **Inefficient** (unnecessary repeated queries)
- **Potentially costly** (AWS API rate limits)

## Solution: Server-Side Caching

The axiom-bridge now caches fleet data with a configurable TTL (Time To Live).

### How It Works

1. **First Request**: Fetches fresh data from AWS via `axiom-ls --json`
2. **Subsequent Requests**: Returns cached data if cache is still valid (within TTL)
3. **Cache Expiry**: After TTL expires, next request fetches fresh data
4. **Force Refresh**: Use `?refresh=true` parameter to bypass cache

### Configuration

Set cache TTL via environment variable (default: 30 seconds):

```bash
export FLEET_CACHE_TTL=60  # Cache for 60 seconds
python3 tools/axiom-bridge.py
```

### API Usage

```bash
# Normal request (uses cache if available)
curl http://localhost:5000/api/fleet

# Force refresh (bypasses cache, queries AWS directly)
curl http://localhost:5000/api/fleet?refresh=true
```

### Dashboard Behavior

- **Dashboard Home**: Checks every 60s, but uses cache (only queries AWS every 30s by default)
- **Fleet Page**: Shows "Force Refresh" button to manually bypass cache
- **Result**: AWS only queried when cache expires or manually refreshed

### Performance Improvement

- **Before**: Every page load = AWS query (~3s delay)
- **After**: First load = AWS query (~3s), subsequent loads = instant (cached)

### Tuning Recommendations

- **Heavy fleet activity**: Lower TTL (10-15s) for near real-time updates
- **Stable fleet**: Higher TTL (60-120s) to minimize AWS queries
- **Production**: Set `FLEET_CACHE_TTL=45` for good balance

## Alternative Approaches Considered

1. **Client-side filtering** - Still requires full AWS query
2. **AWS CLI with filters** - Not supported by axiom-ls wrapper
3. **WebSocket live updates** - Overkill for this use case
4. **Database persistence** - Adds complexity, cache TTL is simpler
