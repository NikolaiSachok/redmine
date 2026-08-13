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
  # Reads the permissions column back as an array of symbols without ever
  # handing the stored string to a YAML parser, so a crafted value cannot
  # become an object graph. Copied from Role::PermissionsAttributeCoder, with
  # one deliberate difference: nil round-trips as nil rather than as an empty
  # array, because for a token those two mean opposite things -- nil is "not
  # restricted", an empty list is "allowed nothing".
  class PermissionsCoder
    # The characters a permission name may contain for this coder to read back
    # what it wrote. load is a scan for symbol names, so :viewIssues would be
    # stored whole and read back as :view -- a scope meaning something other
    # than what was validated, which is the worst failure shape available here.
    # Core Redmine registers no such name and Role's coder has the same
    # limitation; a plugin may. Rather than store a lie, such a name becomes
    # UNREPRESENTABLE below and the whole scope is refused.
    NAME = /[a-z0-9_]+/
    ENTIRE_NAME = /\A#{NAME}\z/
    SERIALIZED_NAME = /:(#{NAME})/

    # Stands in for anything that is not a permission name this coder can carry
    # unchanged. It is in no vocabulary, so the model's validation refuses any
    # scope containing it, which is how a value the coder cannot represent
    # becomes an invalid record rather than a quietly different scope.
    UNREPRESENTABLE = :__unrepresentable__

    def self.load(str)
      return nil if str.nil?

      str.to_s.scan(SERIALIZED_NAME).flatten.map(&:to_sym)
    end

    # True when this coder can store the name and read the same one back.
    def self.round_trips?(name)
      ENTIRE_NAME.match?(name.to_s)
    end

    # Total on purpose. dump is not only called on the way to the column: Rails
    # type-casts a serialized attribute by dumping and re-loading it, both when
    # it is assigned and again when a failed save rolls back and the record
    # state is snapshotted. Raising here would turn "this scope is invalid"
    # into an exception from inside a callback, so nothing is refused at this
    # layer -- what cannot be represented is marked, and the model refuses it.
    #
    # Blanks are dropped rather than marked: they are what the creation form's
    # empty hidden field posts so that unticking every box submits something.
    def self.dump(value)
      return nil if value.nil?

      names = (value.is_a?(Array) ? value : [value]).reject {|name| name.to_s.empty?}
      YAML.dump(names.map {|name| round_trips?(name) ? name.to_s.to_sym : UNREPRESENTABLE})
    end
  end

  # Identifies a Redmine personal access token on sight, in a log or a leaked
  # file, the way ghp_ and glpat- do for GitHub and GitLab.
  PREFIX = 'rmpat_'

  # What the creation form offers. "Full access" stores no scope at all;
  # "read only" and "custom" both store a resolved permission list, so a
  # token's meaning is fixed at the moment it is issued and cannot widen later
  # because a plugin added a permission.
  SCOPE_PRESET_FULL = 'full'
  SCOPE_PRESET_READ_ONLY = 'read_only'
  SCOPE_PRESET_CUSTOM = 'custom'
  SCOPE_PRESETS = [SCOPE_PRESET_FULL, SCOPE_PRESET_READ_ONLY, SCOPE_PRESET_CUSTOM].freeze

  # What a create *request* means when it says nothing about scope. The form
  # pre-selects this preset, and MyController applies it to a submission that
  # omits the radio, so a hand-built post cannot arrive at the widest possible
  # credential by saying less than the form does. Assigning nothing at all in
  # code is still unrestricted -- that is what every token issued before scopes
  # existed has -- but no request can reach that state.
  DEFAULT_SCOPE_PRESET = SCOPE_PRESET_READ_ONLY

  # Redmine's :read flag on a permission means "still allowed while the project
  # is closed", which is not quite "does not write": closing and deleting a
  # project are both flagged that way so that a closed project can be reopened
  # or removed. They are the only two, and they are writes, so the read-only
  # preset excludes them by name. Pinned by
  # test_read_only_permissions_should_exclude_the_two_writes_redmine_marks_as_read.
  NOT_ACTUALLY_READ_ONLY = [:close_project, :delete_project].freeze

  # Lifetimes offered by the creation form, in days. The first one is the
  # default: a credential that never expires has to be chosen deliberately.
  LIFETIME_PRESETS_IN_DAYS = [30, 60, 90].freeze
  DEFAULT_LIFETIME_IN_DAYS = LIFETIME_PRESETS_IN_DAYS.first

  # Tokens are kept for a while after they expire so their owner can still see
  # why one stopped working, then swept by redmine:tokens:prune.
  RETENTION_AFTER_EXPIRY_IN_DAYS = 30

  belongs_to :user

  serialize :permissions, :coder => PermissionsCoder

  # There is no path that edits a token, and there must not be: raising the
  # scope of a token that is already in the wild is the same escalation as
  # issuing an over-wide one. This makes that structural rather than a matter
  # of which controller actions happen to exist.
  attr_readonly :permissions

  validates :name, :presence => true, :length => {:maximum => 60}
  validates :name, :uniqueness => {:scope => :user_id, :case_sensitive => true}
  validates :token_digest, :presence => true, :uniqueness => true

  validate :expiry_must_not_be_in_the_past, :on => :create
  validate :lifetime_must_be_one_that_was_offered, :on => :create
  validate :expiry_must_respect_the_administrator_ceiling, :on => :create
  validate :scope_preset_must_be_one_that_was_offered, :on => :create
  validate :permissions_must_be_a_known_non_empty_set

  before_validation :resolve_scope, :on => :create
  before_validation :generate_token, :on => :create

  scope :sorted, lambda {order(:created_at => :desc)}

  # The cleartext token. Only ever available on the instance that generated it:
  # it is never stored and cannot be recovered afterwards.
  attr_reader :value

  class << self
    def digest(value)
      Digest::SHA256.hexdigest(value.to_s)
    end

    # Every permission name a scope may contain. This is the same vocabulary
    # Redmine already uses for OAuth2 scopes
    # (config/initializers/30-redmine.rb), including the synthetic :admin,
    # because the enforcement points are the same ones.
    def scope_vocabulary
      Redmine::AccessControl.permissions.collect(&:name) + [:admin]
    end

    # The permission list behind the "read only" preset.
    def read_only_permissions
      Redmine::AccessControl.permissions.select(&:read?).collect(&:name) - NOT_ACTUALLY_READ_ONLY
    end

    # The permissions the advanced picker offers, grouped the way the roles
    # screen groups them. :admin is offered separately and only to
    # administrators, since it is inert for anybody else.
    def selectable_permissions
      Redmine::AccessControl.permissions
    end

    # Administrator-set ceiling on token lifetime, in days, or nil when the
    # installation does not set one.
    def max_lifetime_in_days
      days = Setting.personal_access_token_max_lifetime_days.to_i
      days > 0 ? days : nil
    end

    # With a ceiling in place a token must expire, so "No expiration" is not
    # offered and the presets above it are dropped.
    def expiry_required?
      max_lifetime_in_days.present?
    end

    def offered_lifetimes_in_days
      max = max_lifetime_in_days
      return LIFETIME_PRESETS_IN_DAYS.dup unless max

      offered = LIFETIME_PRESETS_IN_DAYS.select {|days| days <= max}
      offered.presence || [max]
    end

    def default_lifetime_in_days
      offered_lifetimes_in_days.first
    end

    # Removes tokens that expired long enough ago to be of no further interest.
    # Called by redmine:tokens:prune alongside Token.destroy_expired.
    def destroy_expired(retention_days = RETENTION_AFTER_EXPIRY_IN_DAYS)
      where(:expires_on => ...(Date.today - retention_days)).delete_all
    end

    # Returns the token for the given cleartext value, or nil
    def find_by_value(value)
      value = value.to_s
      return nil unless value.start_with?(PREFIX)

      find_by(:token_digest => digest(value))
    end

    # Returns the active user owning a usable token with this value, or nil,
    # recording the use on the token.
    #
    # How a request authenticated is a property of the request, not of the
    # user, so it is stamped on the returned object and never persisted. Both
    # stamps are set here, in one place, because the last time one of them was
    # set somewhere else it was silently dropped by impersonation.
    def authenticate(value)
      token = find_by_value(value)
      return nil unless token&.usable?

      token.record_use
      user = token.user
      user.authenticated_by_personal_access_token = true
      user.personal_access_token_scope = token.permissions
      user
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

  # True when the token carries a permission scope. A token created before
  # scopes existed has none, and keeps the full access it was issued with.
  def scoped?
    !permissions.nil?
  end

  # True when everything the scope names is a read. Used for the label only;
  # enforcement never asks this question, it intersects the list.
  def read_only?
    scoped? && permissions.any? && (permissions - self.class.read_only_permissions).empty?
  end

  # Lifetime in days, as offered by the creation form. Blank means no expiry:
  # the choice is explicit either way, rather than defaulting to a credential
  # that never dies.
  attr_reader :expires_in_days

  def expires_in_days=(days)
    @expires_in_days = days.presence
    self.expires_on = days.present? ? User.current.today + days.to_i : nil
  end

  # Which preset the creation form offered, if it was used. Purely an input:
  # what is stored is always the resolved permission list, or nothing at all.
  attr_reader :scope_preset

  def scope_preset=(preset)
    @scope_preset = preset.presence
  end

  private

  # Resolved in a callback rather than in the writer so the result cannot
  # depend on the order the request happened to send its parameters in: a form
  # that posted permissions[] after scope_preset=full would otherwise store the
  # picker's selection and ignore the preset.
  def resolve_scope
    # A preset the form never offered names nothing, so it resolves nothing:
    # scope_preset_must_be_one_that_was_offered refuses the record rather than
    # letting an unrecognised value fall through and behave like "custom".
    return unless @scope_preset.nil? || SCOPE_PRESETS.include?(@scope_preset)

    case @scope_preset
    when SCOPE_PRESET_FULL
      self.permissions = nil
    when SCOPE_PRESET_READ_ONLY
      self.permissions = self.class.read_only_permissions
    when SCOPE_PRESET_CUSTOM
      # The picker's own selection is what gets stored, validated below. A
      # custom scope that names nothing has to become an empty list rather than
      # stay nil: nil means unrestricted, so a submission with no box ticked
      # and no hidden field would otherwise resolve to full access.
      self.permissions = Array(permissions)
    end
    # With no preset at all, whatever was assigned to permissions is the scope,
    # and nil there still means unrestricted -- which is what every token
    # issued before scopes existed has. No request lands there: MyController
    # supplies DEFAULT_SCOPE_PRESET when the form does not, so that case is the
    # console and plugins only.
    #
    # Names posted as strings are already symbols by the time they can be read
    # back: assigning a serialized attribute type-casts it through the coder.
  end

  # scope_preset is an input rather than a stored attribute, so a value that is
  # not one of the three has no meaning: it names no preset and it is not the
  # picker. Refusing it is what makes SCOPE_PRESETS the definition of what may
  # be asked for, rather than a list documenting three of the infinitely many
  # strings that would otherwise be treated as "custom".
  def scope_preset_must_be_one_that_was_offered
    if @scope_preset.present? && !SCOPE_PRESETS.include?(@scope_preset)
      errors.add(:scope_preset, :inclusion)
    end
  end

  # A scope narrows, so an unknown name in the list can never widen anything --
  # it simply intersects with nothing. It is still refused, because a scope
  # that silently ignores half of what it was given is not a scope its owner
  # can reason about. An *empty* list is refused for a harder reason: Rails'
  # blank? treats it the same as no scope at all, and Role#allowed_permissions
  # reads a blank scope as unrestricted, so storing one would fail open.
  #
  # The coder normalises on assignment -- Rails type-casts a serialized
  # attribute by dumping and re-loading it -- so what is checked here is always
  # nil or a list of symbols, whatever shape the caller assigned. That is also
  # what refuses a value the coder cannot carry, such as a mixed-case plugin
  # permission name: it arrives here as PermissionsCoder::UNREPRESENTABLE,
  # which is in no vocabulary.
  def permissions_must_be_a_known_non_empty_set
    return if permissions.nil?

    if permissions.empty?
      errors.add(:permissions, :blank)
    elsif (permissions - self.class.scope_vocabulary).any?
      errors.add(:permissions, :invalid)
    end
  end

  def expiry_must_not_be_in_the_past
    if expires_on.present? && expires_on < User.current.today
      errors.add(:expires_on, :invalid)
    end
  end

  # A crafted request could otherwise send any number here: a huge one buys a
  # token that never expires without choosing "No expiration", and a
  # non-numeric one becomes 0 and expires the same day.
  def lifetime_must_be_one_that_was_offered
    if @expires_in_days.present? && !self.class.offered_lifetimes_in_days.include?(@expires_in_days.to_i)
      errors.add(:expires_on, :invalid)
    end
  end

  # Enforced on the model rather than in the form, so a crafted request cannot
  # outlive the policy either.
  def expiry_must_respect_the_administrator_ceiling
    max = self.class.max_lifetime_in_days
    return if max.nil?

    if expires_on.nil?
      errors.add(:expires_on, :blank)
    elsif expires_on > User.current.today + max
      errors.add(:expires_on, :invalid)
    end
  end

  def generate_token
    @value = PREFIX + Redmine::Utils.random_hex(20)
    self.token_digest = self.class.digest(@value)
  end
end
