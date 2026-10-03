# Autonomous Git Conflict Resolution & Three-Way Diff Protocol

When a task branch encounters merge conflicts against `origin/main`, you must resolve them autonomously without aborting or leaving unmerged conflict markers. Follow this exact execution protocol:

## 1. Upstream Sync & Conflict Identification
- Always sync against `origin/main` using merge, not rebase, to avoid duplicate commit replaying:
  ```bash
  git fetch origin main
  git merge origin/main --no-edit || true
  ```

- Identify conflicting files:
  ```bash
  git status --porcelain | grep '^UU\|^AA\|^DU\|^UD' | awk '{print $2}'
  ```

## 2. File-Specific Resolution Strategies

### A. Append-Only Files (e.g., .jules/sentinel.md, changelogs, audit logs)
Standard line-by-line three-way diffs fail on append-only logs because both branches add entries at the bottom.
- **Rule:** Never attempt line-by-line reconciliation on append-only journals.
- **Resolution Recipe:**
  1. Restore the base file cleanly from origin/main:
     ```bash
     git checkout origin/main -- .jules/sentinel.md
     ```
  2. Append your task-specific entry cleanly to the bottom:
     ```bash
     cat << 'EOF' >> .jules/sentinel.md

### <Task / Name Title Vulnerability>
- **Vulnerability**: <Brief summary>
- **Root Cause**: <Root cause>
- **Enforced Policy**: <Policy details>
- **Task ID**: <Active ID Task>
EOF
     ```
  3. Stage the file:
     ```bash
     git add .jules/sentinel.md
     ```

### B. Source Code Files & Test Suites
- **Rule:** Reconcile both sides semantically. Retain upstream architecture changes and dependency imports from `origin/main` while preserving the security fix or feature introduced by the current task.
- Remove all conflict markers (`<<<<<<< HEAD`, `=======`, `>>>>>>>`).
- Never leave syntax-breaking stubs or mismatched variable definitions.

## 3. Mandatory Pre-Commit Validation Gate
Before staging and committing resolved files, run these three checks in sequence. If any check fails, do not commit:
- **Conflict Marker Audit** (Must return 0 matches):
  ```bash
  ! grep -rnE '^(<{7}|={7}|>{7})(\s|$)' .
  ```
- **Syntax Compilation Check** (Must return exit code 0):
  ```bash
  python3 -m py_compile $(git diff --name-only origin/main | grep '\.py$')
  ```
- **Regression Test Suite** (Must pass with exit code 0):
  ```bash
  PYTHONPATH=. python3 -m unittest discover -s tests -p "test_*.py" -v
  ```

## 4. Finalize and Push
Once verification passes:
```bash
git add -A
git commit -m "chore: resolve merge conflicts against origin/main and verify test suite"
git push origin HEAD
```

## 5. Fail-Safe: Fast-Forward Re-Branch
If git index state becomes wedged or corrupted during resolution:
- Stash your isolated file changes:
  ```bash
  git diff origin/main -- <target_files> > /tmp/task_patch.diff
  ```
- Reset branch to `origin/main`:
  ```bash
  git fetch origin main
  git reset --hard origin/main
  ```
- Apply patch, verify tests, commit, and force-push:
  ```bash
  git apply /tmp/task_patch.diff
  # Re-run Section 3 validation gate
  git commit -am "fix: <task commit message>"
  git push --force-with-lease origin HEAD
  ```
