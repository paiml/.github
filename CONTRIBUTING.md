# Contributing to paiml

paiml does not accept fork contributions, in any repository.

Only authorized collaborators contribute, by pushing a branch in the repository itself
and opening a pull request from that branch. A pull request whose head is a fork:

- starts no CI job on our runners (every reusable-workflow job is guarded on the head repo),
- fails its required `gate` check, and
- is closed automatically by `fork-pr-closer` with a pointer to this file.

## Requesting collaborator access

Open an issue titled `Collaborator access: <repo>` in this repository (paiml/.github),
or email noah@paiml.com. State which single repository you need and why. Access is granted
named, least-privilege, one repository at a time. Once granted, push a branch to that
repository and open the PR from it.
