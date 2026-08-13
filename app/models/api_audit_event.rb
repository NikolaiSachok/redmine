# frozen_string_literal: true

# Redmine - project management software
# Copyright (C) Jean-Philippe Lang
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

# One row per audited REST API call: who, what, when, where, and what came back.
#
# Rows are written once and never updated, so the table carries created_on and
# no updated_on. What decides whether a row is written at all lives here rather
# than in the controller: it is a policy question, and it is the same policy the
# administration screen names.
#
# Two properties are deliberate and are what the design rests on:
#
# * **No credential value is ever stored.** A personal access token is
#   referenced by its id; an API key, a password and a bearer token are not
#   recorded at all, and neither is the query string, which is where a +?key=+
#   would be. Only +request.path+ is kept.
# * **Retention deletes by age, never by count.** Flooding the log therefore
#   costs disk but cannot push earlier evidence out of it, which a
#   "keep the newest N rows" policy would allow by design.
class ApiAuditEvent < ApplicationRecord
  # Off, or the two levels the administration screen offers. The default is
  # deliberately not "everything": a mid-size instance is 90-95% polling GETs,
  # and "who changed what, and who tried to get in" is what an audit trail is
  # for.
  LEVEL_OFF = 'off'
  LEVEL_WRITES = 'writes'
  LEVEL_ALL = 'all'
  LEVELS = [LEVEL_OFF, LEVEL_WRITES, LEVEL_ALL].freeze

  # Request methods that only read. Everything else counts as a write at the
  # writes level, including verbs Redmine does not itself use, because an
  # unexpected verb reaching an action is worth a row.
  READ_METHODS = %w(GET HEAD OPTIONS).freeze

  # Statuses that mean the request was refused rather than served: no
  # credential or a bad one (401), a credential that was not allowed to do this
  # (403), and an X-Redmine-Switch-User naming somebody who cannot be switched
  # to (412). These are the "authentication failures" half of the default
  # level, and they are recorded whether the request was a read or a write.
  REFUSAL_STATUSES = [401, 403, 412].freeze

  # Every text column is a string column, and a value long enough to be
  # truncated by the database is a value somebody is playing with.
  TEXT_LIMIT = 255

  # Vocabulary for the credential_type column. Names how the request
  # authenticated, never what it authenticated with.
  CREDENTIAL_API_KEY = 'api_key'
  CREDENTIAL_PERSONAL_ACCESS_TOKEN = 'personal_access_token'
  CREDENTIAL_OAUTH = 'oauth'
  CREDENTIAL_HTTP_BASIC = 'http_basic'
  CREDENTIAL_TYPES = [
    CREDENTIAL_API_KEY,
    CREDENTIAL_PERSONAL_ACCESS_TOKEN,
    CREDENTIAL_OAUTH,
    CREDENTIAL_HTTP_BASIC
  ].freeze

  # No foreign keys and no dependent options anywhere: an audit row outlives
  # everything it points at, which is the point of it.
  belongs_to :user, :optional => true
  belongs_to :impersonator, :class_name => 'User', :optional => true
  belongs_to :personal_access_token, :optional => true

  scope :sorted, lambda {order(:created_on => :desc, :id => :desc)}

  class << self
    # The configured level, falling back to the default rather than raising if
    # the setting holds something this version does not know about.
    def level
      value = Setting.rest_api_audit_level.to_s
      LEVELS.include?(value) ? value : LEVEL_WRITES
    end

    # True when anything at all is recorded. Checked first on every request, so
    # it does no more than read a memoised setting.
    def recording?
      level != LEVEL_OFF
    end

    # Whether a request is recorded at the configured level.
    #
    # +credential_rejected+ is the honest half of "authentication failures".
    # The status alone is not enough: an HTML request carrying a bad API key is
    # answered with a 302 to the login form, which no list of refusal statuses
    # can distinguish from the redirect that follows a successful write.
    def records?(http_method, status, credential_rejected = false)
      case level
      when LEVEL_OFF
        false
      when LEVEL_ALL
        true
      else
        write?(http_method) || refusal?(status) || credential_rejected
      end
    end

    def write?(http_method)
      !READ_METHODS.include?(http_method.to_s.upcase)
    end

    def refusal?(status)
      REFUSAL_STATUSES.include?(status.to_i)
    end

    # Configured retention in days, or nil when rows are kept forever.
    def retention_in_days
      days = Setting.rest_api_audit_retention_days.to_i
      days > 0 ? days : nil
    end

    # Removes events older than the configured retention. Called by
    # redmine:api_audit:prune.
    #
    # By age, never by count: a caller who floods the log can make it big, but
    # cannot make it forget anything it had before the flood started.
    def prune(days = retention_in_days)
      return 0 if days.nil?

      where(:created_on => ...(days.days.ago)).delete_all
    end

    # Strips control characters and clips to what the column can hold, so
    # nothing a request supplies can forge the shape of a row -- an embedded
    # newline in an audit trail is how one entry becomes two.
    #
    # scrub first: a header can carry bytes that are not valid UTF-8, and the
    # regexp below would raise on those.
    def clean(value, limit = TEXT_LIMIT)
      return nil if value.nil?

      value.to_s.scrub('').gsub(/[[:cntrl:]]/, '')[0, limit]
    end
  end

  # The acting identity as it should be read, which is the stored login rather
  # than the association: the account may be gone, and that is precisely when
  # the row matters most.
  def user_label
    login.presence || user&.to_s
  end

  def impersonator_label
    impersonator_login.presence || impersonator&.to_s
  end

  # True when the call was made through X-Redmine-Switch-User.
  def impersonated?
    impersonator_id.present? || impersonator_login.present?
  end
end
