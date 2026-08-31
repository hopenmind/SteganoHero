# Security Policy

SteganoHero is private software by Hope 'n Mind. This policy explains how the tool is built to be safe to run and how to report a security concern.

## Reporting a vulnerability

If you find a security issue, contact the copyright holder, Hope 'n Mind, privately. Do not open a public issue and do not disclose the details publicly before the issue has been addressed. Please include what you observed, how to reproduce it, and the impact you expect. You will get an acknowledgement, and a fix will be prioritised according to severity.

## How the tool is built to be safe

- **Offline by default.** The desktop app runs fully offline in a native window. It makes no network call at runtime, embeds every dependency, and reaches its engine in-process, with no browser and no server.

- **Local servers stay local.** The optional REST server binds to the local loopback address only. The optional assistant-facing server speaks over a local transport. Neither exposes the tool to the network unless you deliberately configure it to.

- **Authenticated confidentiality.** When a confidentiality layer is applied to hidden content, it uses authenticated encryption with a key derived from your passphrase through a memory-hard function. Two laboratory reference layers exist for study only, are clearly labelled as providing no authentication, and must never be used for anything real.

- **Explicit, labelled outbound steps.** Any step that would send your text to an external service is an explicit, labelled choice, never a silent route. It is refused by name unless you have acknowledged that it leaves your machine, and it is followed by a local re-clean.

- **No silent degradation.** An operation that cannot keep its promise stops and names itself, rather than returning a partial or altered result that looks complete. This is a deliberate defence: it is what prevents a quiet failure from hiding a real problem.

## Scope and honest limits

- The tool cleans your own content. It is not designed to defeat a third party's detection, and it does not claim to prove that a text was written by a human.
- A statistical, word-choice watermark lives in the wording, not in the bytes, and no cleaning operation is guaranteed to remove it. The tool states this limit and never sells a guarantee it cannot keep.
- Some marks are inherently detectable. The tool reports that plainly rather than presenting them as invisible.

## Supported versions

This is actively developed private software. Security fixes are applied to the current line of development.
