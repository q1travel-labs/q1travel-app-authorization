# @q1travel/app-authorization-chrome-extension

Unpublished `0.1.0` candidate for a Chrome extension authorization runtime and
its secret-free UI facade.

The production entry exposes two factories, the sole Operation-catalog compiler
and safe result, snapshot, termination, runtime and UI types. The runtime
factory constructs the session repository, tab coordinator, authorization
coordinator and Task 3 `BackgroundRuntime` in-package, installs their Chrome
listeners, and adds the V2 dispatcher on the shared internal-message port. The
consumer supplies only low-level service-worker resources: trusted session
storage, Chrome runtime/tab/window/alarm ports, crypto, authorization state,
profile preparation and token exchange. The dispatcher verifies the extension
sender, top frame, exact entry path and operation caller policy.

`authorizedFetch` accepts only a package-compiled, opaque Operation catalog.
Each entry defines literal allowed UI callers and exact input/output data
schemas. A facade's literal context filters its callable operation IDs at type
check time. JavaScript string content cannot be completely proven by
TypeScript, so the compiler also rejects dangerous IDs/schema keys at runtime;
arbitrary URLs, headers, raw responses and credential-shaped data fail closed.
All UI messages use closed V2 envelopes, bounded data parsing and fresh decoded
copies. Non-V2 messages are synchronously declined so the Task 3 bootstrap
listener retains ownership. Consumer conformance utilities are compiled and
available only from the `/testing` export.

The `BackgroundOnly*` dependency types intentionally include the minimum
code-verifier and grant material required inside the trusted extension service
worker. They are not imported by `UiFacade`, `UiTransport`, the Operation
catalog or their declaration graph. UI messages cannot carry those values.

This candidate has no npm registry provenance and does not establish any
consumer integration. Building or dry-running the package is not publication
approval.
