# Operator-policy vectors (JEP-0011 §5.1)

`vectors.json` checks the rule that decides whether a server runs a program.

- `policies`: each operator policy as its deterministic-CBOR payload, in hex. A conforming host
  decodes it and refuses it unless it re-encodes to exactly these bytes.
- `cases`: a program's facts, taken from its verified manifest, plus any pinned children, and
  whether the named policy allows the program and each child on its own (`allowed`).

The cases pin these edges:
- a renderer that requests nothing and pins nothing runs by component hash, even when another
  server authored it;
- a bot, a renderer that requests a capability, and a renderer that pins a child do not run by
  component alone;
- `programs` and `authors` admit any world;
- an author's allowance does not cover children by other authors.

The runner is `repos/jig-core/tests/operator_policy_vectors.rs`. To regenerate after an intended
change, run it with `JIG_BLESS_OPERATOR_POLICY_VECTORS=1` and review the diff.
