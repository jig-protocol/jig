# jig-nameserver perf harness

Two ways to run:

1) Self-host mode (spins up an in-process server with memory storage):

```bash
cargo run -p jig-nameserver --bin jig-nameserver-perf -- \
  --self-host --endpoint challenge --requests 1000 --concurrency 50 --subject alice@example.com
```

2) Against a running server:

```bash
# In one terminal
cargo run -p jig-nameserver --release

# In another terminal
cargo run -p jig-nameserver --bin jig-nameserver-perf -- \
  --url http://127.0.0.1:7070 --endpoint resolve --requests 2000 --concurrency 100 --subject alice@example.com
```

Results are written under `repos/jig-nameserver/perf/results/<timestamp>.json` and a summary is printed to stdout.

Tuning tips:
- For open instances, consider: `JIG_NS_POW_DIFFICULTY=18`, `JIG_NS_ANON_MIN_POW=24`, `JIG_NS_RATE_PER_IP_PER_MIN=120`.
- For closed/enterprise, disable anonymous aliasing: `JIG_NS_ANON_ENABLED=false`.

