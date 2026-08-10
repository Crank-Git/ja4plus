---
paths:
  - "*.md"
  - "docs/**/*.md"
  - ".claude/rules/*.md"
  - "ja4plus/**/*.py"
  - "tests/**/*.py"
  - "examples/**/*.py"
---

# Writing standard (STE)

Every spec file, issue body, pull-request comment, manual page and **code comment** in
this project uses Simplified Technical English. A requirement that reads two ways gets
built two ways.

The project's controlled vocabulary is the `## Terms` table in `docs/specs/spec.md`.
Read it before you write a domain word. A term renamed there is a spec change, not a
wording change. When you need a word the table does not hold, add it to the table.

## What is not rewritten

Reproduce these verbatim. Rewriting evidence destroys it, and rewriting a quote
misrepresents the person.

- Anything quoted from a person. Quote it, then restate it below if it needs clarifying.
- Evidence: error messages, log excerpts, test names, stack traces, command output, and
  `file:line` references.
- Code, configuration, commands, JSON, file paths, identifiers and label names.
- Third-party product names, API field names, and text copied from the FoxIO material.

## The rules

### Sentences

1. A procedure sentence is 20 words or fewer. A description sentence is 25 or fewer.
2. One instruction per sentence.
3. One topic per paragraph, six sentences at most.
4. Put the condition first, then the action. "If the vector fails, read the raw form."
5. Put a warning before the step it applies to, never after.

### Words

6. One word, one meaning, one part of speech.
7. One concept, one word. Never rotate synonyms for variety.
8. Keep noun clusters to three words.
9. No metaphor, idiom or slang. State the mechanism instead.
10. No abbreviation the project has not defined.

### Grammar

11. Active voice. "The processor evicts the entry", not "The entry is evicted."
12. Present tense for behaviour. Imperative for instructions.
13. Keep the articles. Write "the state table", not "state table".
14. No `-ing` form as a noun or as a heading. "Batching" becomes "How to form a batch".
15. Write positively. State what to do.
16. Use a vertical list whenever a sentence would carry more than two conditions.

## The one exemption

**Rule 1 exempts two records, and it exempts no other document.** The user ruled on
2026-08-10, on #457.

- The entries of `CHANGELOG.md`, which each record one round.
- The `## Changelog` table of `docs/specs/spec.md`, which holds one row for each round.

**A record states a past measurement, and this project quotes such a record.** A rewrite
of the 159 rows falsifies nothing they record. It does mean that the text a past reader
saw is not the text a future reader sees.

**Warning: read the exemption as these two records alone.** A file whose name holds the
word `changelog` holds the limit. `docs/CHANGELOG.md` is such a file. Every other rule
of this standard reaches both records, among them one word one meaning, active voice, and
the verbatim list above.

Where a self-review finds a Changelog row past the limit, read this section and record
nothing. #393 raised the second such finding, and #457 ends them.

`tests/test_changelog_sentence_exemption.py` reads this section against the tracked
document list of git. A third record that claims the exemption fails a case there.

## Patterns

**A functional requirement.** One testable statement, active voice, no conjunction.

```
Bad:  FR-x-3 — JA4SSH should be able to emit fingerprints periodically.
Good: FR-x-3 — JA4SSH emits one fingerprint for every 200 SSH packets on a connection.
      FR-x-4 — JA4SSH emits no fingerprint before the window fills.
```

**An acceptance criterion.** The observable result, not the implementation.

```
Bad:  JA4SSH works correctly.
Good: `ssh.pcapng` produces exactly one JA4SSH fingerprint.
      That fingerprint equals `c36s36_c76s124_c0s0`.
```

**An issue title.** Imperative verb, one deliverable, 10 words or fewer.

```
Bad:  ja4ssh stuff / window fixes (part 2)
Good: Emit a JA4SSH fingerprint every 200 SSH packets
```

**A code comment.** One sentence, one fact, active voice. Say why, not what. Name the
reason a reader cannot see from the code.

```python
# Bad
# increment the counter
count += 1

# Good
# FoxIO emits one fingerprint per 200 SSH packets. A smaller window produces a
# fingerprint that no reference implementation will match.
SSH_WINDOW = 200
```

**A docstring** opens with one sentence that states the result. Then the parameters,
then the failure modes. No `-ing` opener.

```python
def lookup(fingerprint: str) -> LookupResult | None:
    """Return the application that matches the fingerprint.

    Args:
        fingerprint: A JA4+ fingerprint string.

    Returns:
        The match, or None when the mapping file holds no entry.
    """
```

**A test name is a sentence.** One behaviour, present tense, active voice:
`emits no fingerprint before the window fills`, not `test ssh window stuff 2`.

**A marker comment** keeps its keyword, because tooling matches on it. Write the body to
this standard and name the issue:

```python
# TODO(#412): Read the propagation factor from the FoxIO hop-count table.
```

## Check before you save the file

- [ ] No sentence is longer than 25 words. No instruction is longer than 20. The one
      exemption above covers two records.
- [ ] Every step holds one instruction.
- [ ] Every condition comes before its action. Every warning comes before its step.
- [ ] Every domain word is in the `## Terms` table, with one meaning.
- [ ] No synonym rotation.
- [ ] No noun cluster longer than three words.
- [ ] No metaphor, idiom, or undefined abbreviation.
- [ ] Active voice, present tense, articles present, no `-ing` nouns or headings.
- [ ] Quotes, evidence, code, paths and identifiers are verbatim.
- [ ] Code comments state the reason. Docstrings open with the result. Test names read
      as one behaviour.
