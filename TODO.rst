TODO
====

This file is a scratch pad for ideas and issues which should be address but didn't make it to the issue tracker (yet).

For 0.1.0-beta
--------------

This is the very first release for our beta-testers. Following issues should be addressed before the release:
- [SOL-765] Decide on used license (MIT currently used).
- [SOL-757] Exception handling - wrap httpx exception into something useful.
- [SOL-758] Add delegate to a given identity
- [SOL-759] Provide means to log communication (event hooks for request+response)
- [SOL-757] Doc: Minimal documentation - quickstart
- Enhance example code to show how endorsement verification is done.
- Write test code for providing different option combinations for put/get (and implicitly Request)
- separate tests into tests which should be read form users and internal (devloper) tests.

Before going public on github/PyPi
----------------------------------

Issue to address for public release:
- CI build should run integration tests against developer platform
  - Write tox session to run integration tests.
- Enhance contribution guide about
  - how we expect to write commit messages (see
    https://www.freecodecamp.org/news/writing-good-commit-messages-a-practical-guide/)
      feat: ....
      fix: #12 ...
      style: ...
- See https://cjolowicz.github.io/posts/hypermodern-python-06-ci-cd/
    - Create codecov account
    - Create PyPI account
- Should documentation be hosted on Read the Docs? If not, we should remove dev package dependencies.

Enhancements for future versions
--------------------------------

- provide iov42.core.put() and iov42.core.get() for one time requests similar
  how the HTTP client libraries (requests, httpx) provide.

Internal refactorings
---------------------
- Provide clean interfaces for used 3rd party libraries to that people can use
  alternative implementations.
  - crypto library: can the type annotations be improved?
  - HTTP client library:
    - packaging has to be changed so the httpx implementation is provided as
      optional package.
    - provide documentation how to implement a HttpClient.
    - separate tests against the HttpClient interface.
- Provide clean interface for BaseEntity.
