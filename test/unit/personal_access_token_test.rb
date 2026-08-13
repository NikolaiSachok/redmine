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

class PersonalAccessTokenTest < ActiveSupport::TestCase
  def setup
    User.current = nil
    @user = User.find(2)
  end

  def test_create_should_generate_a_prefixed_value
    token = PersonalAccessToken.create!(:user => @user, :name => 'CI')
    assert token.value.start_with?('rmpat_')
    assert_equal 46, token.value.length
  end

  def test_create_should_store_only_a_digest
    token = PersonalAccessToken.create!(:user => @user, :name => 'CI')
    assert_equal Digest::SHA256.hexdigest(token.value), token.token_digest
    assert_not_equal token.value, token.token_digest
    # the cleartext value must not be recoverable from the database
    row = PersonalAccessToken.connection.select_one(
      "SELECT * FROM personal_access_tokens WHERE id = #{token.id}"
    )
    assert_not_include token.value, row.values.map(&:to_s)
  end

  def test_value_should_not_be_available_after_reload
    token = PersonalAccessToken.create!(:user => @user, :name => 'CI')
    assert_not_nil token.value
    assert_nil PersonalAccessToken.find(token.id).value
  end

  def test_user_should_be_able_to_hold_several_tokens
    assert_difference 'PersonalAccessToken.count', 3 do
      3.times {|i| PersonalAccessToken.create!(:user => @user, :name => "token #{i}")}
    end
    assert_equal 3, @user.personal_access_tokens.count
  end

  def test_name_should_be_required
    token = PersonalAccessToken.new(:user => @user)
    assert !token.save
    assert token.errors[:name].present?
  end

  def test_name_should_be_unique_per_user
    PersonalAccessToken.create!(:user => @user, :name => 'CI')
    duplicate = PersonalAccessToken.new(:user => @user, :name => 'CI')
    assert !duplicate.save
    # but another user may use the same name
    assert PersonalAccessToken.new(:user => User.find(3), :name => 'CI').save
  end

  def test_expired
    assert_not PersonalAccessToken.new(:expires_on => nil).expired?
    assert_not PersonalAccessToken.new(:expires_on => User.current.today).expired?
    assert_not PersonalAccessToken.new(:expires_on => User.current.today + 1).expired?
    assert PersonalAccessToken.new(:expires_on => User.current.today - 1).expired?
  end

  def test_usable_should_be_false_for_a_locked_user
    token = PersonalAccessToken.create!(:user => @user, :name => 'CI')
    assert token.usable?
    @user.update_columns(:status => User::STATUS_LOCKED)
    assert_not token.reload.usable?
  end

  def test_authenticate_should_return_the_user
    token = PersonalAccessToken.create!(:user => @user, :name => 'CI')
    assert_equal @user, PersonalAccessToken.authenticate(token.value)
  end

  def test_authenticate_should_return_nil_for_an_unknown_value
    PersonalAccessToken.create!(:user => @user, :name => 'CI')
    assert_nil PersonalAccessToken.authenticate('rmpat_' + Redmine::Utils.random_hex(20))
  end

  def test_authenticate_should_return_nil_without_the_prefix
    token = PersonalAccessToken.create!(:user => @user, :name => 'CI')
    assert_nil PersonalAccessToken.authenticate(token.value.sub('rmpat_', ''))
  end

  def test_authenticate_should_return_nil_for_an_expired_token
    token = PersonalAccessToken.create!(:user => @user, :name => 'CI')
    token.update_column(:expires_on, User.current.today - 1)
    assert_nil PersonalAccessToken.authenticate(token.value)
  end

  def test_should_not_be_created_with_an_expiry_in_the_past
    token = PersonalAccessToken.new(:user => @user, :name => 'CI',
                                    :expires_on => User.current.today - 1)
    assert !token.save
    assert token.errors[:expires_on].present?
  end

  # ATTACKS.md PAT-005: a crafted lifetime must not buy a token that never
  # expires without choosing "No expiration", nor one that expires today.
  def test_pat_005_lifetime_must_be_one_of_the_offered_presets
    ['99999999', 'abc', '0', '-1', '45'].each do |days|
      token = PersonalAccessToken.new(:user => @user, :name => "t#{days}",
                                      :expires_in_days => days)
      assert !token.save, "expected #{days.inspect} to be rejected"
      assert token.errors[:expires_on].present?
    end

    PersonalAccessToken::LIFETIME_PRESETS_IN_DAYS.each do |days|
      assert PersonalAccessToken.new(:user => @user, :name => "ok#{days}",
                                     :expires_in_days => days).save
    end
  end

  def test_expires_in_days_should_set_the_expiry_date
    token = PersonalAccessToken.create!(:user => @user, :name => 'CI', :expires_in_days => '30')
    assert_equal User.current.today + 30, token.expires_on

    never = PersonalAccessToken.create!(:user => @user, :name => 'forever', :expires_in_days => '')
    assert_nil never.expires_on
  end

  def test_authenticate_should_return_nil_for_a_locked_user_and_the_user_again_once_unlocked
    token = PersonalAccessToken.create!(:user => @user, :name => 'CI')
    @user.update_columns(:status => User::STATUS_LOCKED)
    assert_nil PersonalAccessToken.authenticate(token.value)

    @user.update_columns(:status => User::STATUS_ACTIVE)
    assert_equal @user, PersonalAccessToken.authenticate(token.value)
  end

  def test_authenticate_should_record_the_use
    token = PersonalAccessToken.create!(:user => @user, :name => 'CI')
    assert_nil token.last_used_on
    PersonalAccessToken.authenticate(token.value)
    assert_not_nil token.reload.last_used_on
  end

  def test_administrator_ceiling_should_require_an_expiry_within_it
    with_settings :personal_access_token_max_lifetime_days => '60' do
      assert PersonalAccessToken.expiry_required?
      assert_equal [30, 60], PersonalAccessToken.offered_lifetimes_in_days

      # no expiry is no longer allowed
      never = PersonalAccessToken.new(:user => @user, :name => 'never', :expires_in_days => '')
      assert !never.save
      assert never.errors[:expires_on].present?

      # nor is a lifetime beyond the ceiling, even from a crafted request
      beyond = PersonalAccessToken.new(:user => @user, :name => 'beyond')
      beyond.expires_on = User.current.today + 61
      assert !beyond.save

      assert PersonalAccessToken.new(:user => @user, :name => 'ok', :expires_in_days => '60').save
    end
  end

  def test_administrator_ceiling_below_the_smallest_preset_should_still_offer_one
    with_settings :personal_access_token_max_lifetime_days => '7' do
      assert_equal [7], PersonalAccessToken.offered_lifetimes_in_days
      assert_equal 7, PersonalAccessToken.default_lifetime_in_days
    end
  end

  def test_no_ceiling_by_default
    assert_nil PersonalAccessToken.max_lifetime_in_days
    assert_not PersonalAccessToken.expiry_required?
    assert_equal 30, PersonalAccessToken.default_lifetime_in_days
  end

  def test_destroy_expired_should_sweep_only_long_expired_tokens
    kept_forever = PersonalAccessToken.create!(:user => @user, :name => 'no expiry')
    recently_expired = PersonalAccessToken.create!(:user => @user, :name => 'recent')
    recently_expired.update_column(:expires_on, Date.today - 1)
    long_expired = PersonalAccessToken.create!(:user => @user, :name => 'old')
    long_expired.update_column(:expires_on, Date.today - 400)

    assert_difference 'PersonalAccessToken.count', -1 do
      PersonalAccessToken.destroy_expired
    end
    assert PersonalAccessToken.exists?(kept_forever.id)
    assert PersonalAccessToken.exists?(recently_expired.id), 'kept so the owner can see why it stopped working'
    assert_not PersonalAccessToken.exists?(long_expired.id)
  end

  def test_destroying_a_user_should_destroy_their_tokens
    token = PersonalAccessToken.create!(:user => @user, :name => 'CI')
    @user.destroy
    assert_nil PersonalAccessToken.find_by_id(token.id)
  end
  # --- scopes (issue #5) ---------------------------------------------------

  def test_a_token_should_be_unscoped_by_default
    token = PersonalAccessToken.create!(:user => @user, :name => 'CI')
    assert_nil token.reload.permissions
    assert_not token.scoped?
    assert_not token.read_only?
  end

  # Redmine's :read flag means "still allowed while the project is closed",
  # which is not the same as "does not write": closing and deleting a project
  # are both flagged that way. A preset built straight from the flag would hand
  # a read-only token the power to delete the project it can read.
  def test_read_only_permissions_should_exclude_the_two_writes_redmine_marks_as_read
    flagged = Redmine::AccessControl.permissions.select(&:read?).collect(&:name)
    assert_includes flagged, :delete_project
    assert_includes flagged, :close_project

    assert_not_includes PersonalAccessToken.read_only_permissions, :delete_project
    assert_not_includes PersonalAccessToken.read_only_permissions, :close_project
    assert_includes PersonalAccessToken.read_only_permissions, :view_issues
    assert_equal flagged.size - 2, PersonalAccessToken.read_only_permissions.size
  end

  def test_read_only_preset_should_store_the_resolved_permission_list
    token = PersonalAccessToken.create!(:user => @user, :name => 'CI',
                                        :scope_preset => 'read_only')
    assert_equal PersonalAccessToken.read_only_permissions.sort, token.reload.permissions.sort
    assert token.scoped?
    assert token.read_only?
    assert_not_includes token.permissions, :admin
  end

  def test_custom_preset_should_store_the_selection_as_symbols
    token = PersonalAccessToken.create!(:user => @user, :name => 'CI',
                                        :scope_preset => 'custom',
                                        :permissions => ['', 'view_issues', 'edit_issues'])
    assert_equal [:view_issues, :edit_issues], token.reload.permissions
    assert token.scoped?
    assert_not token.read_only?
  end

  # The preset has to win over whatever the picker posted, whichever order the
  # request happened to send the two parameters in.
  def test_full_preset_should_win_over_a_posted_permission_list
    token = PersonalAccessToken.create!(:user => @user, :name => 'CI',
                                        :permissions => ['admin'],
                                        :scope_preset => 'full')
    assert_nil token.reload.permissions

    other = PersonalAccessToken.create!(:user => @user, :name => 'CI2',
                                        :scope_preset => 'full',
                                        :permissions => ['admin'])
    assert_nil other.reload.permissions
  end

  # ATTACKS.md SCOPE-008: the classic fail-open. Role#allowed_permissions reads
  # a blank scope as "unrestricted", so an empty list must never be stored.
  def test_scope_008_an_empty_scope_should_be_refused
    token = PersonalAccessToken.new(:user => @user, :name => 'CI',
                                    :scope_preset => 'custom', :permissions => [''])
    assert_not token.save
    assert token.errors[:permissions].present?

    assert_not PersonalAccessToken.new(:user => @user, :name => 'CI',
                                       :permissions => []).save
  end

  # ATTACKS.md SCOPE-008: an unknown name cannot widen anything, since a scope
  # only intersects -- but a scope that silently drops half of what it was given
  # is not one its owner can reason about.
  def test_scope_008_an_unknown_permission_should_be_refused
    token = PersonalAccessToken.new(:user => @user, :name => 'CI',
                                    :scope_preset => 'custom',
                                    :permissions => ['view_issues', 'not_a_permission'])
    assert_not token.save
    assert token.errors[:permissions].present?
  end

  def test_admin_should_be_part_of_the_scope_vocabulary
    assert_includes PersonalAccessToken.scope_vocabulary, :admin
    assert PersonalAccessToken.new(:user => @user, :name => 'CI',
                                   :scope_preset => 'custom',
                                   :permissions => ['admin']).save
  end

  # ATTACKS.md SCOPE-007: the column is a stored string an attacker with write
  # access to the database could craft. It is never handed to a YAML parser --
  # the coder scans for symbol names and nothing else -- so there is no
  # deserialization sink here, whatever the value contains.
  def test_scope_007_the_permissions_column_should_never_be_deserialized_as_yaml
    token = PersonalAccessToken.create!(:user => @user, :name => 'CI',
                                        :scope_preset => 'read_only')
    payload = "--- !ruby/object:Gem::Requirement\nrequirements: :view_issues\n"
    # written straight to the row, the way a value crafted outside ActiveRecord
    # would arrive
    PersonalAccessToken.connection.execute(
      "UPDATE personal_access_tokens SET permissions = #{PersonalAccessToken.connection.quote(payload)} WHERE id = #{token.id}"
    )

    loaded = token.reload.permissions
    assert_equal [:view_issues], loaded
    assert loaded.all?(Symbol), "expected only symbols, got #{loaded.inspect}"
    assert_equal [:view_issues], PersonalAccessToken::PermissionsCoder.load(payload)
  end

  def test_the_permissions_coder_should_round_trip_nil_as_nil
    assert_nil PersonalAccessToken::PermissionsCoder.load(nil)
    assert_nil PersonalAccessToken::PermissionsCoder.dump(nil)
    dumped = PersonalAccessToken::PermissionsCoder.dump(['view_issues', :edit_issues])
    assert_equal [:view_issues, :edit_issues], PersonalAccessToken::PermissionsCoder.load(dumped)
  end

  # ATTACKS.md SCOPE-004: raising the scope of a token already in the wild is
  # the same escalation as issuing an over-wide one, so the column is readonly.
  def test_scope_004_the_scope_should_not_be_editable_after_creation
    token = PersonalAccessToken.create!(:user => @user, :name => 'CI',
                                        :scope_preset => 'read_only')
    token.permissions = [:admin]
    token.save!
    assert_equal PersonalAccessToken.read_only_permissions.sort, token.reload.permissions.sort
  end

  def test_authenticate_should_stamp_the_scope_on_the_returned_user
    token = PersonalAccessToken.create!(:user => @user, :name => 'CI',
                                        :scope_preset => 'read_only')
    user = PersonalAccessToken.authenticate(token.value)
    assert user.authenticated_by_personal_access_token?
    assert user.scoped_by_personal_access_token?
    assert_equal token.reload.permissions.sort, user.personal_access_token_scope.sort
  end

  def test_authenticate_should_leave_an_unscoped_token_unscoped
    token = PersonalAccessToken.create!(:user => @user, :name => 'CI')
    user = PersonalAccessToken.authenticate(token.value)
    assert user.authenticated_by_personal_access_token?
    assert_not user.scoped_by_personal_access_token?
    assert_nil user.request_permission_scope
  end
end
