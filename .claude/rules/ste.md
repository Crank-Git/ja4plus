---
paths:
  - "*.md"
  - "docs/**/*.md"
  - "docs/specs/*.html"
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
- A document heading a case reads by string, and every citation of that heading.

### The spellings rule 17 keeps

**Warning: read this section before you move a British spelling.** Rule 17 moves no span
this section names, and a sweep by pattern that skipped this section would falsify a
record.

**Rule 17 moves none of these five.**

1. A Markdown quotation, which opens the line with `>`. A quotation is evidence.
2. A word inside a code span, which the list above already reproduces verbatim.
3. The two records that `## The exemption` names.
4. A span the list below names, in a file the same item names.
5. `tests/test_us_english_spelling.py`, which states every British spelling it detects.

**Each item names the span first and the path second, and each one is a code span.** The
path is a git pathspec, and the reader matches a span without regard to its case. This
list keeps every span an identifier, a heading or a quotation holds.

- `Behaviour rule` in `*`. It opens the heading `## Behaviour rules` of eleven feature
  pages, and it opens every citation of that heading. `tests/test_documentation_behaviour_rule.py`
  reads the heading by string.
- `BehaviourRules` in `tests/*.py`. The case name `TestTheBehaviourRulesNameOneCommand`
  holds the same heading as one word.
- `behaviour_rules` in `tests/*.py`. It is a function name.
- `test_documentation_behaviour_rule` in `*`. It is a module name, which is a file path.
- `neighbour` in `tests/state_readers.py`. The constant names `NEIGHBOUR_CLIENT` and
  `NEIGHBOUR_SERVER` hold it, and so do the parameter names that read them.
- `neighbour` in `tests/test_cleanup_connection.py`. Four parameter names hold it.
- `neighbour` in `tests/test_foxio_citation_lines.py`. The fixture file name `neighbour.md`
  holds it, and so does the local name that reads it.
- `cancelled` in `tests/test_batch_gate.py`. It is the run conclusion the provider writes.
- `preserves the present behaviour` in `tests/test_delegated_ruling_rule.py`. The
  maintainer stated the delegation on 2026-08-15 in these words.
- `unlabelled` in `tests/test_spec_validation.py`. It is a function name.
- `acknowledgement` in `*`. American English holds this form beside `acknowledgment`, so
  rule 17 states no preference.

**Warning: `towards` is a usage choice and it is no spelling.** Rule 17 reaches it nowhere.

**Warning: bar 2 costs the sweep every word a writer puts in backticks.** A reader who
wants rule 17 to reach a word writes that word as prose.

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
17. US English spelling. Write `behavior`, `neighbor`, `analyze` and `labeled`, and never
    the British form of the same word.

### Grammar

11. Active voice. "The processor evicts the entry", not "The entry is evicted."
12. Present tense for behavior. Imperative for instructions.
13. Keep the articles. Write "the state table", not "state table".
14. No `-ing` form as a noun or as a heading. "Batching" becomes "How to form a batch".
15. Write positively. State what to do.
16. Use a vertical list whenever a sentence would carry more than two conditions.

## The exemption

**Rule 1, rule 3 and rule 17 exempt two records, and they exempt no other document.** The
user ruled on 2026-08-10, on #457 for rule 1 and on #502 for rule 3. The maintainer ruled
rule 17 on 2026-08-16, on #663.

- The entries of `CHANGELOG.md`, which each record one round.
- The `## Changelog` table of `docs/specs/spec.md`, which holds one row for each round.

**A record states a past measurement, and this project quotes such a record.** A rewrite
of the 190 rows falsifies nothing they record. It does mean that the text a past reader
saw is not the text a future reader sees.

**One row records one round, which is one topic.** The sentence count of a row follows
from how much that round measured. A read of 2026-08-10 reports 178 of the 190 rows past
six sentences, and 113 of the 136 entries of `CHANGELOG.md` past six.

**The exemption covers rule 1, rule 3 and rule 17.** It covers the word limit of a
sentence, the sentence limit of a paragraph and the spelling of a word. It covers no other
rule of this standard.

**Rule 17 exempts the same two records, and the maintainer stated the reason on
2026-08-16.** The documentation of this repository is largely agent-written, so a worker
that matches the surrounding spelling strengthens a convention no person chose. The
maintainer ruled US English to end that loop. **A record is the one text the ruling does
not reach.** A record states a past measurement, and a rewrite of its spelling leaves a
future reader a text that no past reader saw. The sweep of #663 therefore moved no entry of
`CHANGELOG.md` and no row of the `## Changelog` table.

**Every other rule reaches both records: rules 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
and 16.** Among them stand one instruction per sentence, one word one meaning, active
voice, and the verbatim list above.

**Warning: read the exemption as these two records alone.** A file whose name holds the
word `changelog` holds both limits. `docs/CHANGELOG.md` is such a file.

Where a self-review finds a Changelog row past either limit, read this section and record
nothing. #393 raised the rule-1 finding and #457 ended it. The self-review of #484 raised
the rule-3 finding and #502 ends it.

`tests/test_changelog_sentence_exemption.py` reads this section against the tracked
document list of git and against the numbered rule list above. A third record that claims
the exemption fails a case there. A rule the section places nowhere fails one too, so an
eighteenth rule needs a reading before it ships. #663 gave rule 17 that reading on
2026-08-16.

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

**A test name is a sentence.** One behavior, present tense, active voice:
`emits no fingerprint before the window fills`, not `test ssh window stuff 2`.

**A marker comment** keeps its keyword, because tooling matches on it. Write the body to
this standard and name the issue:

```python
# TODO(#412): Read the propagation factor from the FoxIO hop-count table.
```

## Check before you save the file

- [ ] No sentence is longer than 25 words. No instruction is longer than 20. The
      exemption above covers rule 1 for two records.
- [ ] No paragraph holds more than six sentences. The exemption above covers rule 3 for
      the same two records.
- [ ] Every step holds one instruction.
- [ ] Every condition comes before its action. Every warning comes before its step.
- [ ] Every domain word is in the `## Terms` table, with one meaning.
- [ ] No synonym rotation.
- [ ] No noun cluster longer than three words.
- [ ] No metaphor, idiom, or undefined abbreviation.
- [ ] Active voice, present tense, articles present, no `-ing` nouns or headings.
- [ ] Quotes, evidence, code, paths and identifiers are verbatim.
- [ ] Code comments state the reason. Docstrings open with the result. Test names read
      as one behavior.
