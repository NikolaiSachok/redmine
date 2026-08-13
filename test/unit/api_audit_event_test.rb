# frozen_string_literal: true

# Redmine - project management software
# Copyright (C) 2006-  Jean-Philippe Lang
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

require_relative '../test_helper'

class ApiAuditEventTest < ActiveSupport::TestCase
  def setup
    User.current = nil
    ApiAuditEvent.delete_all
  end

  def generate_event(attributes = {})
    ApiAuditEvent.create!({
      :login => 'jsmith',
      :user_id => 2,
      :credential_type => ApiAuditEvent::CREDENTIAL_API_KEY,
      :http_method => 'POST',
      :endpoint => 'issues#create',
      :path => '/issues.json',
      :ip => '10.0.0.1',
      :status => 201,
      :created_on => Time.now
    }.merge(attributes))
  end

  # -- level policy ---------------------------------------------------------

  def test_level_should_default_to_writes
    assert_equal ApiAuditEvent::LEVEL_WRITES, Setting.rest_api_audit_level
    assert_equal ApiAuditEvent::LEVEL_WRITES, ApiAuditEvent.level
    assert ApiAuditEvent.recording?
  end

  def test_an_unrecognised_level_should_read_as_the_default
    with_settings :rest_api_audit_level => 'verbose' do
      assert_equal ApiAuditEvent::LEVEL_WRITES, ApiAuditEvent.level
    end
    with_settings :rest_api_audit_level => '' do
      assert_equal ApiAuditEvent::LEVEL_WRITES, ApiAuditEvent.level
    end
  end

  def test_off_should_record_nothing
    with_settings :rest_api_audit_level => 'off' do
      assert_not ApiAuditEvent.recording?
      assert_not ApiAuditEvent.records?('POST', 201)
      assert_not ApiAuditEvent.records?('GET', 401)
      assert_not ApiAuditEvent.records?('GET', 200, true)
    end
  end

  def test_writes_should_record_writes_refusals_and_rejected_credentials_only
    with_settings :rest_api_audit_level => 'writes' do
      %w(POST PUT PATCH DELETE).each do |method|
        assert ApiAuditEvent.records?(method, 200), "#{method} should be recorded"
      end
      %w(GET HEAD OPTIONS).each do |method|
        assert_not ApiAuditEvent.records?(method, 200), "#{method} should not be recorded"
      end
      [401, 403, 412].each do |status|
        assert ApiAuditEvent.records?('GET', status), "#{status} should be recorded"
      end
      [200, 302, 404, 500].each do |status|
        assert_not ApiAuditEvent.records?('GET', status), "#{status} should not be recorded"
      end
      # a credential offered and rejected, whatever status followed
      assert ApiAuditEvent.records?('GET', 302, true)
    end
  end

  def test_all_should_record_every_request
    with_settings :rest_api_audit_level => 'all' do
      assert ApiAuditEvent.records?('GET', 200)
      assert ApiAuditEvent.records?('HEAD', 304)
    end
  end

  def test_an_unknown_verb_should_count_as_a_write
    with_settings :rest_api_audit_level => 'writes' do
      assert ApiAuditEvent.records?('PROPFIND', 200)
    end
  end

  # -- field cleaning (AUDIT-001) -------------------------------------------

  def test_clean_should_remove_control_characters
    assert_equal '10.0.0.1x', ApiAuditEvent.clean("10.0.0.1\r\nx")
    assert_equal 'ab', ApiAuditEvent.clean("a\tb")
    assert_equal 'ab', ApiAuditEvent.clean("a\0b")
  end

  def test_clean_should_clip_to_the_column_width
    assert_equal ApiAuditEvent::TEXT_LIMIT, ApiAuditEvent.clean('a' * 1000).length
    assert_equal 10, ApiAuditEvent.clean('a' * 1000, 10).length
  end

  def test_clean_should_survive_bytes_that_are_not_valid_utf8
    cleaned = ApiAuditEvent.clean((+"a\xC3(b\nc").force_encoding('UTF-8'))
    assert cleaned.valid_encoding?
    assert_equal 'a(bc', cleaned
  end

  def test_clean_should_pass_nil_through
    assert_nil ApiAuditEvent.clean(nil)
  end

  # -- retention (AUDIT-R4 / AUDIT-R12) -------------------------------------

  def test_retention_should_read_the_setting_and_treat_zero_as_forever
    with_settings :rest_api_audit_retention_days => '30' do
      assert_equal 30, ApiAuditEvent.retention_in_days
    end
    with_settings :rest_api_audit_retention_days => '0' do
      assert_nil ApiAuditEvent.retention_in_days
    end
  end

  def test_prune_should_remove_events_older_than_the_retention
    old = generate_event(:created_on => 100.days.ago)
    recent = generate_event(:created_on => 10.days.ago)

    with_settings :rest_api_audit_retention_days => '90' do
      assert_difference 'ApiAuditEvent.count', -1 do
        ApiAuditEvent.prune
      end
    end

    assert_nil ApiAuditEvent.find_by_id(old.id)
    assert_not_nil ApiAuditEvent.find_by_id(recent.id)
  end

  def test_audit_003_prune_should_remove_by_age_so_a_flood_cannot_evict_earlier_evidence
    evidence = generate_event(:created_on => 10.days.ago, :endpoint => 'issues#destroy')
    # the flood: many rows, all newer than the evidence
    50.times {generate_event(:created_on => 1.hour.ago)}

    with_settings :rest_api_audit_retention_days => '90' do
      ApiAuditEvent.prune
    end

    assert_not_nil ApiAuditEvent.find_by_id(evidence.id),
                   'a flood of newer rows must not push an older one out of the log'
  end

  # Prune runs in batches so that SQLite's single write lock is held for one
  # chunk at a time: unbatched, this was 2.7-2.9s for 50,000 rows on the
  # measurement machine, and every audited request is itself an INSERT, so the
  # log blocked its own producers while it pruned.
  #
  # Asserted through behaviour rather than by counting statements: what must
  # hold is that a backlog larger than one batch is fully removed, that rows
  # inside the retention survive, and that the count returned is the count
  # actually deleted.
  def test_prune_should_remove_a_backlog_larger_than_one_batch
    12.times {|i| generate_event(:created_on => (100 + i).days.ago)}
    keeper = generate_event(:created_on => 1.day.ago)

    removed = nil
    deletes = 0
    counter = lambda do |*, payload|
      deletes += 1 if payload[:sql].to_s.match?(/\ADELETE/i)
    end

    assert_difference 'ApiAuditEvent.count', -12 do
      ActiveSupport::Notifications.subscribed(counter, 'sql.active_record') do
        removed = ApiAuditEvent.prune(90, :batch_size => 5)
      end
    end

    assert_equal 12, removed, 'prune must report what it actually deleted'
    # 5 + 5 + 2. The count is the property: one statement means one write lock
    # held for the whole backlog, which is the defect this method was changed to
    # avoid.
    assert_equal 3, deletes, 'the backlog must be removed in batches, not as one statement'
    assert_not_nil ApiAuditEvent.find_by_id(keeper.id)
    assert_equal 0, ApiAuditEvent.where(:created_on => ...(90.days.ago)).count
  end

  # A batch size that exceeds the backlog must behave exactly as before, so the
  # batching cannot change the result for the ordinary small case.
  def test_prune_should_be_unchanged_when_the_backlog_fits_in_one_batch
    3.times {generate_event(:created_on => 100.days.ago)}
    generate_event(:created_on => 1.day.ago)

    assert_equal 3, ApiAuditEvent.prune(90)
    assert_equal 1, ApiAuditEvent.count
  end

  # The cutoff is computed once rather than per batch. Recomputing it would let
  # the window slide during a long run and delete rows that were inside the
  # retention period when the task started.
  def test_prune_should_not_delete_rows_that_were_inside_the_retention_when_it_started
    boundary = generate_event(:created_on => 89.days.ago)
    6.times {generate_event(:created_on => 100.days.ago)}

    ApiAuditEvent.prune(90, :batch_size => 2)

    assert_not_nil ApiAuditEvent.find_by_id(boundary.id)
  end

  def test_prune_should_keep_everything_when_retention_is_zero
    generate_event(:created_on => 10.years.ago)

    with_settings :rest_api_audit_retention_days => '0' do
      assert_no_difference 'ApiAuditEvent.count' do
        ApiAuditEvent.prune
      end
    end
  end

  # -- reading a row --------------------------------------------------------

  def test_user_label_should_survive_the_account_being_deleted
    event = generate_event(:user_id => nil, :login => 'gone')
    assert_equal 'gone', event.user_label
    assert_nil event.user
  end

  def test_impersonated_should_be_false_without_an_impersonator
    assert_not generate_event.impersonated?
    assert generate_event(:impersonator_id => 1, :impersonator_login => 'admin').impersonated?
  end

  def test_a_row_should_survive_the_token_it_names_being_revoked
    token = PersonalAccessToken.create!(:user => User.find(2), :name => 'CI')
    event = generate_event(:personal_access_token_id => token.id)
    token.destroy

    event.reload
    assert_equal token.id, event.personal_access_token_id
    assert_nil event.personal_access_token
  end
end
