# Contributing

1. Fork and create a branch.
2. Make your change. Keep the server dependency-free (standard library only).
3. Run `python -m unittest discover -s tests -v` and `python scripts/check_ui.py`.
4. Add a test for any new server behavior, especially anything that touches the filesystem.
5. Open a pull request describing what changed and why.

Security-sensitive changes (anything in `api_plan`, `api_apply`, `api_undo`, `safe_path`) need a test for the failure case too.
