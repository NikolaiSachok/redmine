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

  def test_destroying_a_user_should_destroy_their_tokens
    token = PersonalAccessToken.create!(:user => @user, :name => 'CI')
    @user.destroy
    assert_nil PersonalAccessToken.find_by_id(token.id)
  end
end
