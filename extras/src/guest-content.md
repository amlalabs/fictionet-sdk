# Guest content checks

`guest_content::Audit` inspects bytes explicitly supplied by a world or the kit.
It checks rendered configuration and decoded installed files. HTTP encodings and
ZIP, tar, Debian, gzip, xz and zstd archives are decoded recursively. Inspection
limits and invalid complete archives fail closed.

One shared policy checks internal project names and disclosures of the serving
environment: evaluation machinery, synthetic page provenance, instructions for
the evaluated agent and fixture artifacts. HTML entities, URL escapes and JSON
strings are decoded before matching. The same rules supply the page writer's
prompt, rejection feedback and page diagnostics.

Words about a page's subject are allowed: World Wide Web Consortium, software
tests, benchmark results, sandbox escapes, simulations and expected behavior are
ordinary web language. Style choices such as punctuation are not disclosures.

Article paths `/corvane-acquisition` and `/fastjsonl-package` describe their
subjects; bare internal names remain forbidden. Unmodified vendor archives may
contain their own testing machinery, but internal project names are still checked.
First-party pages and installed tools receive the full disclosure check.

The page writer retries a rejected answer with that answer and the named issue.
Rejections and recovery are world observations. Answers stopped by the provider's
output limit are also rewritten as shorter complete documents. Repeated rejection
uses the world's local renderer and established context, never the rejected
bytes. Transport failures and invalid answer formats remain explicit failures.
