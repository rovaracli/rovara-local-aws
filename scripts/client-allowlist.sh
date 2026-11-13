#!/usr/bin/env bash
# Client allow-list gate: fails if a class that opens an outbound connection (an HTTP, socket or URL
# client) appears in src/main that is not on the reviewed list. A merge from upstream cannot quietly
# add one: a new file shows up here and must be reviewed, fenced (core/common/OutboundFence) and
# given a no-outbound test before it is added below.
set -u
cd "$(dirname "$0")/.."
REVIEWED='
src/main/java/ai/rovara/localaws/services/sns/SnsService.java            fenced: OutboundFence in deliverable(); test OutboundFenceTest
src/main/java/ai/rovara/localaws/services/sagemaker/SageMakerRuntimeController.java   fenced: OutboundFence.requireAllowed; test OutboundFenceTest
src/main/java/ai/rovara/localaws/services/lambda/launcher/FunctionRunnerClient.java   fenced: OutboundFence.requireAllowed in the constructor, no redirects, bounded reply; test FunctionRunnerClientTest
'
allowed=$(printf '%s\n' "$REVIEWED" | awk 'NF{print $1}')
PATTERN='java\.net\.http|HttpURLConnection|URLConnection|openConnection\(|new Socket\(|DatagramSocket|SocketChannel\.open|createHttpClient|createNetClient|WebClient|RestClient|OkHttp|HttpClient\.new|io\.vertx\.core\.http\.HttpClient|io\.vertx\.ext\.web\.client|org\.apache\.http|org\.apache\.hc|AsyncHttpClient|ProxySelector|\.toURL\(\)\.open'
found=$(grep -rlE "$PATTERN" src/main/java | sort)
fail=0
for f in $found; do
  if ! printf '%s\n' "$allowed" | grep -qx "$f"; then
    echo "unreviewed outbound client: $f"; grep -nE "$PATTERN" "$f" | head -3; fail=1
  fi
done
[ "$fail" -eq 0 ] && echo "OK: every class with an outbound client is on the reviewed list." && exit 0
echo "FAIL: review, fence and test the file(s) above, then add them to scripts/client-allowlist.sh."
exit 1
