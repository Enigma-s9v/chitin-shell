#!/usr/bin/env bash
# ===========================================================================
# Chitin Shell — Network Isolation Security Test
#
# Verifies that Docker network isolation is working correctly:
#   1. Agent CANNOT reach proxy (direct)
#   2. Agent CANNOT reach external URLs
#   3. Agent CAN reach policy engine
#   4. Policy CAN reach proxy
#   5. Proxy CAN reach external URLs
#   6. Agent has NO secret environment variables
#
# Usage:
#   # From the docker/ directory, with containers running:
#   docker compose exec agent bash /app/test/isolation-test.sh
#
#   # Or run from host:
#   bash test/isolation-test.sh
# ===========================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

PASS=0
FAIL=0
TOTAL=0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log_header() {
  echo ""
  echo -e "${BLUE}══════════════════════════════════════════════════════════${NC}"
  echo -e "${BLUE}  $1${NC}"
  echo -e "${BLUE}══════════════════════════════════════════════════════════${NC}"
}

assert_pass() {
  TOTAL=$((TOTAL + 1))
  PASS=$((PASS + 1))
  echo -e "  ${GREEN}PASS${NC}: $1"
}

assert_fail() {
  TOTAL=$((TOTAL + 1))
  FAIL=$((FAIL + 1))
  echo -e "  ${RED}FAIL${NC}: $1"
}

# Exec a command inside a container, return exit code
docker_exec() {
  local container="$1"
  shift
  docker exec "$container" "$@" 2>/dev/null
  return $?
}

# Try HTTP request from inside a container. Returns 0 if reachable.
try_reach() {
  local container="$1"
  local url="$2"
  local timeout="${3:-5}"

  # Use node since curl may not be installed in slim images
  docker exec "$container" node -e "
    const http = require('http');
    const url = new URL('${url}');
    const req = http.get({
      hostname: url.hostname,
      port: url.port || 80,
      path: url.pathname,
      timeout: ${timeout}000,
    }, (res) => {
      process.exit(0);
    });
    req.on('error', () => process.exit(1));
    req.on('timeout', () => { req.destroy(); process.exit(1); });
  " 2>/dev/null
  return $?
}

# Check if container has an env var matching a pattern
has_env_pattern() {
  local container="$1"
  local pattern="$2"
  docker exec "$container" node -e "
    const found = Object.keys(process.env).some(k => /${pattern}/.test(k));
    process.exit(found ? 0 : 1);
  " 2>/dev/null
  return $?
}

# ---------------------------------------------------------------------------
# Pre-flight: check containers are running
# ---------------------------------------------------------------------------

log_header "Pre-flight Check"

for container in chitin-agent chitin-policy chitin-proxy; do
  if docker inspect --format='{{.State.Running}}' "$container" 2>/dev/null | grep -q true; then
    echo -e "  ${GREEN}OK${NC}: $container is running"
  else
    echo -e "  ${RED}ERROR${NC}: $container is not running. Start with: docker compose up -d"
    exit 1
  fi
done

# ---------------------------------------------------------------------------
# Test 1: Agent CANNOT reach proxy directly
# ---------------------------------------------------------------------------

log_header "Test 1: Agent -> Proxy (should FAIL)"

if try_reach chitin-agent "http://chitin-proxy:3200/health" 5; then
  assert_fail "Agent can reach proxy directly — NETWORK ISOLATION BROKEN!"
else
  assert_pass "Agent cannot reach proxy (connection refused/timeout)"
fi

# ---------------------------------------------------------------------------
# Test 2: Agent CANNOT reach external URLs
# ---------------------------------------------------------------------------

log_header "Test 2: Agent -> Internet (should FAIL)"

if try_reach chitin-agent "http://httpbin.org/get" 5; then
  assert_fail "Agent can reach the internet — NETWORK ISOLATION BROKEN!"
else
  assert_pass "Agent cannot reach external URLs"
fi

if try_reach chitin-agent "http://api.openai.com/v1/models" 5; then
  assert_fail "Agent can reach OpenAI API — NETWORK ISOLATION BROKEN!"
else
  assert_pass "Agent cannot reach OpenAI API"
fi

# ---------------------------------------------------------------------------
# Test 3: Agent CAN reach policy engine
# ---------------------------------------------------------------------------

log_header "Test 3: Agent -> Policy (should PASS)"

if try_reach chitin-agent "http://chitin-policy:3100/health" 5; then
  assert_pass "Agent can reach policy engine"
else
  assert_fail "Agent cannot reach policy engine — routing broken"
fi

# ---------------------------------------------------------------------------
# Test 4: Policy CAN reach proxy
# ---------------------------------------------------------------------------

log_header "Test 4: Policy -> Proxy (should PASS)"

if try_reach chitin-policy "http://chitin-proxy:3200/health" 5; then
  assert_pass "Policy engine can reach proxy"
else
  assert_fail "Policy engine cannot reach proxy — routing broken"
fi

# ---------------------------------------------------------------------------
# Test 5: Proxy CAN reach external URLs
# ---------------------------------------------------------------------------

log_header "Test 5: Proxy -> Internet (should PASS)"

if try_reach chitin-proxy "http://httpbin.org/get" 10; then
  assert_pass "Proxy can reach external URLs"
else
  assert_fail "Proxy cannot reach external URLs — external access broken"
fi

# ---------------------------------------------------------------------------
# Test 6: Agent has NO secret environment variables
# ---------------------------------------------------------------------------

log_header "Test 6: Agent Environment Variables (should have NO secrets)"

if has_env_pattern chitin-agent "^PROXY_"; then
  assert_fail "Agent has PROXY_* env vars — CREDENTIAL LEAK!"
else
  assert_pass "Agent has no PROXY_* env vars"
fi

if has_env_pattern chitin-agent "OPENAI"; then
  assert_fail "Agent has OPENAI env vars — CREDENTIAL LEAK!"
else
  assert_pass "Agent has no OPENAI env vars"
fi

if has_env_pattern chitin-agent "ANTHROPIC"; then
  assert_fail "Agent has ANTHROPIC env vars — CREDENTIAL LEAK!"
else
  assert_pass "Agent has no ANTHROPIC env vars"
fi

if has_env_pattern chitin-agent "SLACK_TOKEN"; then
  assert_fail "Agent has SLACK_TOKEN env var — CREDENTIAL LEAK!"
else
  assert_pass "Agent has no SLACK_TOKEN env var"
fi

if has_env_pattern chitin-agent "SECRET|PRIVATE_KEY|API_KEY"; then
  assert_fail "Agent has SECRET/PRIVATE_KEY/API_KEY env vars — CREDENTIAL LEAK!"
else
  assert_pass "Agent has no SECRET/PRIVATE_KEY/API_KEY env vars"
fi

# ---------------------------------------------------------------------------
# Test 7: Proxy HAS credentials (sanity check)
# ---------------------------------------------------------------------------

log_header "Test 7: Proxy Credentials (sanity check)"

if has_env_pattern chitin-proxy "^PROXY_"; then
  assert_pass "Proxy has PROXY_* credentials loaded"
else
  assert_fail "Proxy has no PROXY_* credentials — vault will be empty"
fi

# ---------------------------------------------------------------------------
# Test 8: End-to-end Intent flow
# ---------------------------------------------------------------------------

log_header "Test 8: End-to-End Intent Flow"

E2E_RESULT=$(docker exec chitin-agent node -e "
  const http = require('http');
  const payload = JSON.stringify({
    action: 'think',
    params: { thought: 'Hello from isolation test' }
  });
  const req = http.request({
    hostname: 'localhost',
    port: 3000,
    path: '/intent',
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) },
    timeout: 10000,
  }, (res) => {
    let data = '';
    res.on('data', (c) => data += c);
    res.on('end', () => {
      const j = JSON.parse(data);
      console.log(j.verification?.approved ? 'APPROVED' : 'REJECTED');
    });
  });
  req.on('error', (e) => console.log('ERROR:' + e.message));
  req.write(payload);
  req.end();
" 2>/dev/null)

if [ "$E2E_RESULT" = "APPROVED" ]; then
  assert_pass "End-to-end Intent flow works (think action approved)"
else
  assert_fail "End-to-end Intent flow failed (got: $E2E_RESULT)"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

log_header "Results"

echo ""
echo -e "  Total:  ${TOTAL}"
echo -e "  ${GREEN}Passed: ${PASS}${NC}"
echo -e "  ${RED}Failed: ${FAIL}${NC}"
echo ""

if [ "$FAIL" -eq 0 ]; then
  echo -e "  ${GREEN}ALL TESTS PASSED — Network isolation is secure.${NC}"
  echo ""
  exit 0
else
  echo -e "  ${RED}SECURITY TESTS FAILED — Review the failures above.${NC}"
  echo ""
  exit 1
fi
