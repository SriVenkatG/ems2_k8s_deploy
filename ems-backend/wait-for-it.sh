#!/usr/bin/env bash
# small wait-for-it: wait for host:port then run command
set -e

if [ $# -lt 2 ]; then
  echo "Usage: $0 host:port -- command"
  exit 1
fi

hostport="$1"
shift
if [ "$1" = "--" ]; then shift; fi
cmd="$@"

host="${hostport%%:*}"
port="${hostport##*:}"

timeout=${WAIT_TIMEOUT:-60}
end=$((SECONDS + timeout))

echo "Waiting for $host:$port (timeout ${timeout}s)..."
while ! (echo > /dev/tcp/"$host"/"$port") 2>/dev/null; do
  if [ $SECONDS -ge $end ]; then
    echo "Timeout waiting for $host:$port"
    exit 1
  fi
  sleep 1
done

echo "$host:$port is available Ã¢â‚¬â€ running command"
exec $cmd
