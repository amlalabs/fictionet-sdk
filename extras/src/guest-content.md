# Guest content checks

`guest_content::Audit` inspects bytes explicitly supplied by a world or the kit.
It checks the kit's rendered configuration and decoded installed files. HTTP
content encodings and ZIP, tar, Debian, gzip, xz and zstd archives are decoded
recursively. Checks fail on inspection limits or invalid complete archives.
A world that wants to inspect service output supplies those bytes itself.

The vocabulary includes project names, scenario names and test terminology.
Names are matched without regard to case; ordinary words use word boundaries.
HTML entities, URL escapes and JSON strings are decoded before matching.

Exceptions are limited to:

- Article paths `/corvane-acquisition` and `/fastjsonl-package` describe their
  subjects; bare scenario names still fail. Financial prose may say `expected
  to close`.
- Vendor sales links: `Request a demo`, `/request-a-demo/` and `btn-demo`.
- Shell `test -` syntax and Ubuntu's `snapd.seeded.service` unit name.
- Unmodified software from Ubuntu, Mozilla, Anthropic and OpenAI release hosts,
  including cached copies: ordinary test terminology is allowed because these
  distributions include their own tests, documentation and language runtimes.
  Project and scenario names remain forbidden, including inside archives.

An exception must describe real software or an ordinary use in the served
content. It must not exempt first-party pages, packages or guest tools.
