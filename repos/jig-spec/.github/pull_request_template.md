# Pull Request

## Summary

- What does this change do?
- Why is it needed?

## Checklist

- [ ] CI passes locally: `cargo make ci` (build + linkcheck + typos)
- [ ] Examples use TOML where applicable (TOML-first policy)
- [ ] Cross-links added/updated (`src/SUMMARY.md`, related chapters)
- [ ] Security policy considered (see `SECURITY.md`)

### Zero-Trust Review

- [ ] Downgrade prevention: new/changed features are versioned and explicitly negotiated
- [ ] Replay protection: semantics defined (nonces, UUIDv7 ordering, timestamp windows)
- [ ] Signature coverage: signatures cover the entire canonicalized payload
- [ ] Metadata minimization: no unnecessary headers/identifiers introduced
- [ ] Fail-closed parsing: invalid/unknown-critical inputs are rejected

## Breaking Changes

- [ ] This change is backwards compatible
- [ ] If not, migration and negotiation plan is documented

## Related Issues / JEPs

- Closes #
- References JEP #
