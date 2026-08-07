# Merge procedure

```
Document:  docs/MERGE-PROCEDURE.md, version 1.0
Scope:     this repository only. If any of this should become a family
           convention, it travels to WORKFLOW.md as a convention-amendment
           exchange entry (FAMILY.md 3.2), never by editing a vendored copy.
```

Branch protection on `main` is active with `enforce_admins: true`, which
means **nobody pushes to main, including the repository owner**. Every change
is a branch and a pull request. This is deliberate: a protection that admins
can step around protects nobody, and the same reasoning that refuses a
configurable security limit (P6) refuses an admin bypass.

## Repository settings, and why each one

| Setting | Value | Reason |
|---|---|---|
| `enforce_admins` | true | see above |
| required checks | `ruff`, `mypy`, `pytest` | by check-run name, matching `.github/workflows/gate.yml` job names |
| `strict` | true | a branch must be up to date with `main` before merging, so the checks that passed ran against the code that will land |
| squash merge | **disabled** | a version bump is its own commit; squashing a PR that carries one destroys that |
| rebase merge | enabled | preserves the two-commit shape (feature, then bump) |
| merge commit | disabled | keeps history linear |
| auto-merge | enabled | repository setting, per brief section 8 |
| force pushes, deletions | disabled | the branch is not rewritable after protection |

## The procedure

```
git checkout -b feat/<name>
```

Work, then run the local gate before pushing anything:

```
ruff check . && mypy pirx && python -m pytest -q
```

Commit the feature and the version bump separately. **The bump commit must
carry the version change itself** - `pyproject.toml`, `pirx/__init__.py`,
`STATUS.json` - and nothing else. An empty marker commit does not survive a
rebase merge, which discards empty commits, and the tag then lands on a
feature commit (review finding F17). So the feature commit leaves those three
files at the previous version:

```
git add <explicit file list>        # never git add -A, and not the version files
git commit -m "feat: ..."

# now bump, as a commit whose entire diff is the version
git add pyproject.toml pirx/__init__.py STATUS.json
git commit -m "chore: version 0.N.0.0"
git push -u origin feat/<name>
```

Open the PR, then watch the checks **as a separate command**. Chaining them
races GitHub: at the instant the PR is created the check runs may not exist
yet, `--watch` returns immediately with nothing to watch, and the next command
in the chain hits a PR that is not yet mergeable (observed on PR #3).

```
gh pr create --fill --base main
```

```
gh pr checks --watch
```

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

After the rebase, wait for checks again before merging:

```
gh pr checks --watch
gh pr merge --rebase
```

Finally, sync local `main` and push the tag, which does not travel with the
merge:

```
git checkout main && git pull
git push origin v0.N.0.0
```

## Tags and rebase merges

A rebase merge rewrites commit SHAs. A tag created on the branch before the
merge therefore points at a commit that is **not** on `main`. Two honest
options, and this repository takes the second:

1. Tag on the branch, accept that the tag names a pre-rebase commit.
2. **Tag after merging**, on the merged `main`, so `v0.N.0.0` names a commit
   that is actually in the mainline history.

So the tag step above moves to the end of the procedure:

```
git checkout main && git pull
git tag v0.N.0.0 && git push origin v0.N.0.0
```

Verify the tag points where you think it does - separately from creating it,
per P13:

```
git log --oneline -1 v0.N.0.0
```
