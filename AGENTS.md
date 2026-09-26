# Instructions for AI assistants working on this repository

1. Read `docs/DECISIONS.md` before changing anything. Only what is written there is decided.
2. **At the end of every step or significant change**, before stopping:
   - append the decisions and implementation notes to `docs/DECISIONS.md`
     (same table format, next free `D`/`I` number; never rewrite past entries, strike them
     through and point to the replacement);
   - update the local hand-off file `docs/HANDOFF.fr.md` if it exists (git-ignored, French):
     state of each step, next actions, known pitfalls;
   - update `README.md` when behaviour or results change;
   - run the tests (`uv run pytest -q`, `uv run ruff check .`) and `gitleaks detect`, then commit.
   The goal: work can resume at any moment with another assistant, from these files alone.
3. The project is anonymous: no real names, personal handles, real IP ranges or domains in code,
   tests, docs or commit messages. Real logs live only in `data/` (git-ignored).
4. Privacy first: nothing reaches a model without pseudonymisation; never weaken the leak guard.
5. Elastic fixtures (ELv2) are downloaded at run time and never committed or quoted in reports.
