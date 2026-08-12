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

# A named API credential that a user may hold several of, that can expire, and
# that is stored only as a digest.
#
# This is deliberately not a Token action: Token caps the api action at one
# instance per user, computes expiry per action rather than per record, and
# looks tokens up by their cleartext value.
class PersonalAccessToken < ApplicationRecord
  # Identifies a Redmine personal access token on sight, in a log or a leaked
  # file, the way ghp_ and glpat- do for GitHub and GitLab.
  PREFIX = 'rmpat_'

  # Lifetimes offered by the creation form, in days. The first one is the
  # default: a credential that never expires has to be chosen deliberately.
  LIFETIME_PRESETS_IN_DAYS = [30, 60, 90].freeze
  DEFAULT_LIFETIME_IN_DAYS = LIFETIME_PRESETS_IN_DAYS.first

  belongs_to :user

  validates :name, :presence => true, :length => {:maximum => 60}
  validates :name, :uniqueness => {:scope => :user_id, :case_sensitive => true}
  validates :token_digest, :presence => true, :uniqueness => true

  validate :expiry_must_not_be_in_the_past, :on => :create
  validate :lifetime_must_be_one_that_was_offered, :on => :create

  before_validation :generate_token, :on => :create

  scope :sorted, lambda {order(:created_at => :desc)}

  # The cleartext token. Only ever available on the instance that generated it:
  # it is never stored and cannot be recovered afterwards.
  attr_reader :value

  class << self
    def digest(value)
      Digest::SHA256.hexdigest(value.to_s)
    end

    # Returns the token for the given cleartext value, or nil
    def find_by_value(value)
      value = value.to_s
      return nil unless value.start_with?(PREFIX)

      find_by(:token_digest => digest(value))
    end

    # Returns the active user owning a usable token with this value, or nil,
    # recording the use on the token.
    def authenticate(value)
      token = find_by_value(value)
      return nil unless token&.usable?

      token.record_use
      token.user
    end
  end

  # Returns true if the token has passed its expiry date.
  #
  # Evaluated in the owner's time zone, the same one the expiry was chosen in.
  # User.current is the anonymous user while a request is being authenticated,
  # so relying on it here would shift the boundary by up to a day.
  def expired?
    expires_on.present? && expires_on < (user || User.current).today
  end

  # Returns true if the token can currently authenticate a request. Locking a
  # user disables their tokens without destroying them; unlocking restores them.
  def usable?
    !expired? && user.present? && user.active?
  end

  def record_use
    update_column(:last_used_on, Time.now)
  end

  # Lifetime in days, as offered by the creation form. Blank means no expiry:
  # the choice is explicit either way, rather than defaulting to a credential
  # that never dies.
  attr_reader :expires_in_days

  def expires_in_days=(days)
    @expires_in_days = days.presence
    self.expires_on = days.present? ? User.current.today + days.to_i : nil
  end

  private

  def expiry_must_not_be_in_the_past
    if expires_on.present? && expires_on < User.current.today
      errors.add(:expires_on, :invalid)
    end
  end

  # A crafted request could otherwise send any number here: a huge one buys a
  # token that never expires without choosing "No expiration", and a
  # non-numeric one becomes 0 and expires the same day.
  def lifetime_must_be_one_that_was_offered
    if @expires_in_days.present? && !LIFETIME_PRESETS_IN_DAYS.include?(@expires_in_days.to_i)
      errors.add(:expires_on, :invalid)
    end
  end

  def generate_token
    @value = PREFIX + Redmine::Utils.random_hex(20)
    self.token_digest = self.class.digest(@value)
  end
end
