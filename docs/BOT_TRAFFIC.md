# Bot traffic assessments

Open **Bot traffic** after importing Apache access logs for **chronoscrate.xyz**.
Existing imports work after restarting the application. Assessments use stored
evidence and current analyst decisions; no migration or reimport is required.
Plain and gzip imports use the same logic.

Labels implement the requested policy and do not prove an IP is a bot or human.
Bots can request normal pages and legitimate visitors can trigger risk rules.
Review the linked evidence before applying a block. More comprehensive systems
combine multiple kinds of signals; see [Cloudflare's detection engines](https://developers.cloudflare.com/bots/concepts/bot-detection-engines/).

## Categories

Rules are evaluated in this order:

| Category | Evidence | Recommendation |
| --- | --- | --- |
| Confirmed bot | Any risk alert attributed to this IP and linked to access evidence in the selected history | Review for blocking |
| Not a bot | No qualifying risk alert, plus a successful GET of `/` or `/checkout`, or a matching language + HTML + CSS sequence | Allow and monitor |
| Suspected bot | Neither of the above; insufficient normal browsing evidence | Monitor or challenge |

**Any IP-attributed risk alert overrides normal browsing**, regardless of severity.
New, investigating, and resolved alerts count. **False positive** alerts do not.
Changing the last qualifying alert to false positive updates the assessment and
export on refresh. Server-wide HTTP-500 and Apache-error bursts do not identify
an individual malicious visitor and are not assigned to every IP involved.

Suspected bot is an uncertainty category. A missing language header, absent CSS,
or a single unknown-page request alone does not justify a ban. The app exports
recommendations for review and never changes the website or firewall.

## Normal browsing evidence

- Successful retrieval means GET with a 2xx or 304 response. Failed responses,
  redirects, HEAD, and POST do not count as page retrievals.
- `/` and `/checkout` are the configured pages; `/checkout/` also counts.
  Query strings do not change page identity. `/checkout/admin` and `/CHECKOUT`
  are different paths. Percent-encoded paths are not normalized.
- Absolute HTTP(S) targets must name `chronoscrate.xyz`. An absolute request
  for another website's `/checkout` does not count as a visit to this site.
- HTML means a configured page, a `.html`/`.htm` path, or a logged
  `sfd:"document"`. CSS means a `.css` path or `sfd:"style"`. Both require
  successful GETs. These signals describe requests, not verified response bodies.
- A browsing sequence requires a valid language preference, HTML, and CSS
  from the same IP within an inclusive five-minute window. Evidence links point
  to the requests supporting that window. Language or HTML alone is insufficient.
- Language comes from `lang`, `accept-language`, or `accept_language` in
  extended combined evidence. Names are case insensitive. Specific language
  tags with nonzero preference weights count equally, regardless of language.
  Wildcard-only, dash, empty, malformed, missing, or ambiguous repeated fields
  do not supply this signal. Missing fields are shown as unavailable.

[Accept-Language](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Accept-Language)
expresses client language preferences. It does not verify identity. Logs also
cannot show whether the browser rendered HTML/CSS or executed JavaScript.

## Apache logging

Standard common/combined layouts do not log language preferences. The existing
bot-tracking format with `lang:"..."` works as imported. An example Apache
configuration that adds the supported fields is:

```apache
LogFormat "%a %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" lang:\"%{Accept-Language}i\" sfd:\"%{Sec-Fetch-Dest}i\"" bot_tracking
CustomLog logs/bot-tracking-access.log bot_tracking
```

Apache's [mod_log_config reference](https://httpd.apache.org/docs/2.4/mod/mod_log_config.html)
documents the client-IP and request-header directives. Configure logging on the
website's server if needed; the analyzer does not alter server configuration.
Behind a proxy/CDN, verify that the logged IP is the original client before
blocking it. One IP can represent multiple visitors.

Import this site's logs separately. Origin-form Apache requests omit the host,
so the analyzer cannot identify mixed websites from those records. The page
paths come from the supplied requirements; classification never crawls the site.

## Developer workflow

1. Select the source IP and a relevant UTC date range for the incident.
2. Review Confirmed bot IPs first. **Review IP** shows reasons, page/asset/language
   counts, timestamps, and linked evidence. Historical risk alone should not
   automatically produce a permanent block.
3. Open an alert to inspect all evidence or mark it false positive.
4. Select **Export ban candidates** to download `ban-candidates.txt`, with one
   canonical IP per line. Review the list before applying your own controls.

Cards cover the shared IP/date filters. The category selector narrows the table.
Export always contains **all confirmed IPs matching the shared filters**,
regardless of table category or pagination. Unattributed requests are counted
separately and never exported. Details show up to ten recent alert samples and
five browsing-signal links; each alert retains its complete paginated evidence.

## APIs

`GET /api/bots` accepts `source_ip`, `start`, `end`, `classification`, `limit`,
`offset`, and `order`. Categories are `confirmed_bot`, `suspected_bot`, and
`not_a_bot`. Validation and UTC formats match other investigation endpoints.
Categories appear in risk-priority order; `order=desc` (default) or `asc` sorts
last-seen times within each category.

The response contains `items`, `pagination`, `summary`, and `policy`. Each item
includes reasons, recommendation, timestamps, counts, bounded language samples,
risk-alert samples, and browsing event IDs. Summary counts precede the category
filter. Alert attribution uses linked evidence timestamps within the selected
range even if a correlated alert started earlier.

`GET /api/bots/export` accepts only `source_ip`, `start`, and `end` and returns
the text attachment. No confirmed IPs produces an empty file. Both endpoints
are read only, use a consistent database snapshot, and require initialization.
They scan matching history; memory grows with IP count rather than request count.

```powershell
Invoke-RestMethod 'http://127.0.0.1:5000/api/bots?classification=confirmed_bot&limit=25'
Invoke-WebRequest 'http://127.0.0.1:5000/api/bots/export' -OutFile ban-candidates.txt
```

## Synthetic example

Import [bot_traffic.txt](../examples/bot_traffic.txt) as an access log into a
fresh workspace. Eight events produce one sensitive-file alert:

| IP | Category | Reason |
| --- | --- | --- |
| 203.0.113.201 | Confirmed bot | Risk overrides home and checkout visits |
| 203.0.113.202 | Not a bot | Successful home page request |
| 203.0.113.203 | Not a bot | Language preference plus HTML and CSS |
| 203.0.113.204 | Suspected bot | Unknown page; insufficient normal evidence |
| 203.0.113.205 | Suspected bot | Language and CSS without HTML |

The export initially contains only `203.0.113.201`. Mark its alert false positive
and refresh: it becomes Not a bot because of normal-page visits and the export
becomes empty. All addresses are documentation addresses.
