# Deployment runbook

## Preconditions

Confirm the service is healthy before starting. A failed precondition aborts the run.

```bash
systemctl status app.service
curl -sf http://127.0.0.1:8787/health
```

## Sequence

1. Drain traffic from the node and wait for active connections to close.
2. Stop the service. Verify the process exited rather than assuming it did.
3. Replace the binary. Keep the previous one adjacent, named with its version.
4. Start the service and watch the first sixty seconds of logs.
5. Restore traffic only after the health endpoint returns success twice in a row.

## Rollback

If step 5 does not pass within five minutes, stop and restore the previous binary. Do not attempt to diagnose while traffic is degraded. Diagnosis happens after the service is healthy again.

| Signal | Meaning | Action |
|---|---|---|
| Health endpoint times out | Process started but not listening | Rollback |
| Repeated restarts in logs | Configuration mismatch | Rollback, then diff config |
| Latency above baseline | Warm cache not yet populated | Wait, recheck at 10 minutes |

## Notes

The health endpoint binds loopback only. Reaching it from another host means the bind address is wrong, which is itself a fault worth stopping for.
