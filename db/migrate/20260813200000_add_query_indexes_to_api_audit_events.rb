class AddQueryIndexesToApiAuditEvents < ActiveRecord::Migration[7.2]
  # ApiAuditQuery advertises these columns as sortable and groupable, and the
  # table had indexes only on created_on and user_id. Grouping is the expensive
  # case: SQLite answered it with SCAN + USE TEMP B-TREE over the whole table.
  #
  # Measured on 200,000 rows, p50 (method and full numbers in
  # notes/SCALE-AUDIT.md):
  #
  #   ORDER BY status            13.7 ms -> 0.5 ms
  #   GROUP BY endpoint          51.3 ms -> 8.1 ms
  #   GROUP BY http_method       40.7 ms -> 7.7 ms
  #   GROUP BY credential_type   36.9 ms -> 8.0 ms
  #   COUNT ... login LIKE       10.6 ms -> 6.7 ms
  #
  # The low-cardinality columns gain the most because SQLite answers the group
  # from a covering index and never touches the table.
  #
  # The cost side was measured too, because an index is pure overhead on INSERT
  # and this table is written on the request path. An interleaved A/B over two
  # identical databases, 1,200 single-row inserts per arm: p50 -0.7%, mean
  # +1.6% -- below the noise floor, because SQLite's per-statement transaction
  # overhead (~1.6 ms) swamps index maintenance. The measurable cost is disk:
  # 34.7 MB -> 49.5 MB for 200,000 rows, about +43%.
  #
  # path, ip and impersonator_login are sortable but deliberately left
  # unindexed: none of them is groupable, sorting by them is rare, and the
  # default time window already bounds it. Indexes are added for what was
  # measured to hurt, not for every column the query mentions.
  def change
    add_index :api_audit_events, :status
    add_index :api_audit_events, :credential_type
    add_index :api_audit_events, :http_method
    add_index :api_audit_events, :endpoint
    add_index :api_audit_events, :login
  end
end
