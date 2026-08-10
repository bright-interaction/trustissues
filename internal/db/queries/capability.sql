
-- ============================================================================
-- Reading the credential access trail
-- ============================================================================
--
-- capability_log has recorded every capability token issued, spent and denied
-- since 00020, and until now NOTHING read it. No query, no route, no page. For a
-- product whose pitch is that an agent spends a credential it never sees, "which
-- agent spent which secret, when, and to where" is not a diagnostic detail, it is
-- the receipt the whole design exists to produce, and it was write-only.
--
-- 00039 made the table append-only and audit_name_crypto.go sealed secret_name
-- under the audit DEK, so the rows are now both immutable and confidential. Those
-- two passes protected a trail nobody could look at. This is the half that makes
-- them worth having.

-- name: ListCapabilityLog :many
-- Filters compose, deliberately, in ONE statement.
--
-- ListActivityEntriesFiltered's own comment records what the alternative cost:
-- its first cut was a switch whose leading arm won, so choosing a user silently
-- discarded the action filter and the table and its export disagreed. On an audit
-- surface two different answers to the same question is worse than one wrong one,
-- so every filter is ANDed here and the count twin below shares the predicate
-- verbatim.
SELECT id, agent_id, secret_id, secret_name, destination, method, event,
       status_code, error, issued_at
FROM capability_log
WHERE (CAST(@agent_filter AS TEXT) = '' OR agent_id = @agent_filter)
  AND (CAST(@event_filter AS TEXT) = '' OR event = @event_filter)
  AND (CAST(@secret_filter AS TEXT) = '' OR secret_id = @secret_filter)
ORDER BY issued_at DESC, id DESC
LIMIT @lim OFFSET @off;

-- name: CountCapabilityLog :one
-- The same WHERE as ListCapabilityLog. If they ever drift, the pager reports a
-- total the table cannot show.
SELECT COUNT(*) FROM capability_log
WHERE (CAST(@agent_filter AS TEXT) = '' OR agent_id = @agent_filter)
  AND (CAST(@event_filter AS TEXT) = '' OR event = @event_filter)
  AND (CAST(@secret_filter AS TEXT) = '' OR secret_id = @secret_filter);

-- name: ListCapabilityLogAgents :many
-- The distinct agents that appear in the trail, so the filter is a CHOSEN value
-- rather than a typed one. An agent id is an opaque token the operator never
-- memorises; a free-text box over it returns nothing and reads as "no activity".
SELECT DISTINCT agent_id FROM capability_log ORDER BY agent_id;
