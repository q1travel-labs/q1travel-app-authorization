# Agent guidance

- Treat the API V2 JSON fixture as read-only authority: copy upstream changes exactly and update its recorded SHA-256 only with reviewed API evidence.
- Keep `src/core` platform-independent and consumer-neutral; supply runtime capabilities through explicit ports.
- For core changes, prove the focused conformance test red before implementation, then run the focused test and package typecheck green.

