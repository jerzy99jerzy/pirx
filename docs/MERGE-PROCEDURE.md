# Merge procedure

```
Document:  docs/MERGE-PROCEDURE.md, version 1.2
Scope:     this repository only. If any of this should become a family
           convention, it travels to cve-digest as a convention-amendment
           exchange entry (FAMILY.md 3.2). cve-digest's WORKFLOW.md is not
           vendored here (brief section 8), and this document is not
           vendored there.
```

Changes in 1.2: `gh pr create --fill-first`, because `--fill` titles a PR
with more than one commit from its branch name; tags annotated on the merged
bump commit's full hash, each step in its own block, as `v0.7.5.0` was made;
a section for applying a patch series produced outside this clone, with the
tree-hash check; and values written literally or as variables, because
`<n>` in a command block is a redirection in zsh, which made 1.1's
"zsh-safe" untrue in two blocks.

Changes in 1.1: the required-checks row names all four contexts the
protection actually requires; the local gate is described as it runs; a
pre-push checklist carries the topology step (F58-F60); every command block
is zsh-safe and keeps verification apart from the action it checks (P13).

Branch protection on `main` is active with `enforce_admins: true`, which
means **nobody pushes to main, including the repository owner**. Every change
is a branch and a pull request. This is deliberate: a protection that admins
can step around protects nobody, and the same reasoning that refuses a
configurable security limit (P6) refuses an admin bypass.

## Repository settings, and why each one

| Setting | Value | Reason |
|---|---|---|
| `enforce_admins` | true | see above |
| required checks | `ruff`, `mypy`, `docs-audit`, `pytest` | by check-run name, matching `.github/workflows/gate.yml` job names; read from `gh api repos/jerzy99jerzy/pirx/branches/main/protection`, never from what `gh pr checks` renders (F22) |
| `strict` | true | a branch must be up to date with `main` before merging, so the checks that passed ran against the code that will land |
| squash merge | **disabled** | a version bump is its own commit; squashing a PR that carries one destroys that |
| rebase merge | enabled | preserves the two-commit shape (feature, then bump) |
| merge commit | disabled | keeps history linear |
| auto-merge | enabled | repository setting, per brief section 8 |
| force pushes, deletions | disabled | the branch is not rewritable after protection |

## The procedure

Two values are set once per session and read by every block below except the
tag commands, which take no variable (see "Tags and rebase merges"). The
values here are examples:

```
BRANCH=docs/reconcile-0.7.5.1
VERSION=0.7.5.1
```

Branch from the remote's `main`, never from a local `main` that may be
behind:

```
git fetch origin
git checkout -b "$BRANCH" origin/main
```

Work, then run the local gate before pushing anything:

```
ruff check . && mypy pirx && python -m pytest -q
```

The suite runs both documentation audits through `tests/test_docs_audit.py`,
so this line is the whole gate: documentation drift fails here, not after a
push. CI runs the audits again as the separate `docs-audit` job so a failure
names itself.

### Before pushing: the check the gate cannot make

**Topology.** If this version changes how many processes, writers, or readers
touch a shared artefact - the ledger, the spend store, the pending queue, the
key file - search every document and docstring for claims naming the old
count, and re-read each one against the new topology. F58, F59, and F60 were
the same defect three times: a claim true when written, invalidated by a later
version, sitting in a file that version had no reason to open. This is a
checklist line rather than a habit because the habit is what produced three.

Commit the feature and the version bump separately. **The bump commit must
carry the version change itself** - `pyproject.toml`, `pirx/__init__.py`,
`STATUS.json` - and nothing else. An empty marker commit does not survive a
rebase merge, which discards empty commits, and the tag then lands on a
feature commit (review finding F17). So the feature commit leaves those three
files at the previous version.

**Pins.** `STATUS.json` pins the versions the brief, ARCHITECTURE, and
FAMILY.md declare, and the pins move in the bump commit with the version.
README's position marker and badges, and the docstring of
`pirx/__init__.py`, move in the feature commit. The feature commit alone
therefore fails the docs audit on those pins; that is expected, because CI
and the local gate both check the head.

Stage the feature with an explicit file list - never `git add -A` or
`git add .`, and not the version fields. The list and message below are
examples:

```
git add README.md docs/TODO.md
git commit -m "docs: what changed, and why"
```

Then the bump, as a commit whose entire diff is the version:

```
git add pyproject.toml pirx/__init__.py STATUS.json
git commit -m "chore: version $VERSION"
```

Confirm what is about to leave, separately from pushing it (P13):

```
git log --oneline --stat origin/main..HEAD
```

```
git push -u origin "$BRANCH"
```

Open the PR, then watch the checks **as a separate command**. Chaining them
races GitHub: at the instant the PR is created the check runs may not exist
yet, `--watch` returns immediately with nothing to watch, and the next command
in the chain hits a PR that is not yet mergeable (observed on PR #3).

```
gh pr create --fill-first --base main
```

`--fill-first` takes the title and body from the first commit, which is the
feature commit; `--fill` would title a two-commit PR from its branch name.

```
gh pr checks --watch
```

Right after creation this can report no checks at all. Wait and run it
again; "nothing to watch" is not green.

If a merge is refused as not-yet-mergeable, the right answer is to wait or to
queue it:

```
gh pr merge --rebase --delete-branch --auto
```

`--auto` merges once the requirements are met, which is what the repository's
auto-merge setting is for. **`--admin` is forbidden.** `gh` suggests it, and
taking it once turns `enforce_admins` from a control into a suggestion - the
same reasoning that refuses a configurable security limit (P6).

## What `strict: true` costs, stated because it will bite

`strict` requires the branch to be current with `main` at merge time. If
`main` moved while the PR was open, GitHub refuses the merge and **`gh pr
merge` does not fix it for you** - it reports the branch as out of date and
stops. The fix is a rebase, which also re-runs the checks against the merged
state, which is the entire point of the setting:

```
git fetch origin
git rebase origin/main
```

Then force-push the *branch* (allowed; the protection covers `main` only):

```
git push --force-with-lease
```

`--force-with-lease` rather than `--force`: it refuses if someone else moved
the branch since your last fetch. With one contributor the difference is
theoretical today and free, which is the right time to make it a habit.

After the rebase, wait for checks again, and merge as a separate command
once they are green (P13):

```
gh pr checks --watch
```

```
gh pr merge --rebase --delete-branch --auto
```

Then tag, as the last section describes: a tag does not travel with the
merge.

## Applying a patch series produced outside this clone

A version prepared elsewhere - a review container, a second machine -
arrives as `git format-patch` files named for this repository and the
version, `pirx-0.7.5.1-1-feature.patch` and `pirx-0.7.5.1-2-bump.patch`,
never with the bare `0001-` prefix: a downloads directory holding series
from two repositories collides on it.

```
ls ~/Downloads | grep "pirx-$VERSION"
```

Exactly two lines, or stop. Branch from the remote's `main` as above, then
apply:

```
git am ~/Downloads/pirx-$VERSION-1-feature.patch ~/Downloads/pirx-$VERSION-2-bump.patch
```

Check the transfer separately (P13):

```
git log -2 --format='%h %an <%ae> | %s'
git rev-parse 'HEAD~1^{tree}' 'HEAD^{tree}'
```

The author must be the maintainer, because `git am` keeps whoever produced
the patch. The two tree hashes must equal the ones the producer reported.
Commit hashes never match across a transfer - `git am` and the rebase merge
each rewrite the committer - while a tree hash covers every byte of the tree
and survives both, so it is the comparison that shows the tree landed
intact. On 0.7.5.0 they matched at every hop, from the producing container
to the pushed branch to `main`. If `git am` stops, run `git am --abort` and
ask for a series regenerated against the current `origin/main`; do not reach
for `--3way` first.

## Tags and rebase merges

A rebase merge rewrites commit SHAs, so a tag created on the branch points
at a commit that is **not** on `main`. Tags are therefore created after the
merge, on the merged bump commit, **annotated**, and named by that commit's
full hash typed into the command - never through a variable or `$(...)`,
which carries a value across a paste boundary where nobody sees it.
cve-digest's WORKFLOW section 7 holds the same rule. Each step is its own
block (P13):

```
git checkout main
git pull --ff-only origin main
```

```
git log -3 --format='%H %s'
```

The top line must be `chore: version 0.7.5.1` for the version being tagged.
Copy its full hash into the next block by hand, replacing
`BUMP_COMMIT_FULL_HASH`, which git refuses if it is pasted unedited:

```
git tag -a v0.7.5.1 -m "v0.7.5.1: one line on what the version is" BUMP_COMMIT_FULL_HASH
```

```
git cat-file -t v0.7.5.1
git log -1 --format='%H %s' v0.7.5.1
```

Expected: `tag`, then the bump commit's hash and subject. Only then push it:

```
git push origin v0.7.5.1
```

```
git ls-remote --tags origin 'v0.7.5.1*'
```

The `^{}` line must carry the bump commit's hash: it is the commit the
annotated tag points at. The version in these blocks is written literally on
purpose; it is an example, and tag commands are the one place in this
procedure that takes no variable.
