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

module Redmine
  # Cross-origin resource sharing policy for the REST API.
  #
  # The policy is deliberately narrow:
  #
  # * it is off unless an administrator lists at least one origin, and an empty
  #   list means "allow nothing" rather than "allow everything";
  # * an origin matches only if it is byte-for-byte equal to a configured one
  #   after normalisation, so scheme, host and port all have to agree;
  # * +Access-Control-Allow-Credentials+ is never sent, and therefore an
  #   allowed origin can never read a response that was authorised by the
  #   session cookie. Cross-origin callers authenticate with an API key or a
  #   personal access token in a request header, which browsers send without
  #   being in credentials mode.
  module Cors
    # Methods advertised in a preflight response. Fixed rather than reflected
    # from Access-Control-Request-Method: a preflight should say what the API
    # supports, not repeat what the caller asked for.
    ALLOWED_METHODS = 'GET, POST, PUT, PATCH, DELETE, OPTIONS'

    # Request headers a cross-origin caller may send. Fixed for the same
    # reason, and because reflecting Access-Control-Request-Headers turns the
    # allowlist into a rubber stamp.
    ALLOWED_HEADERS = 'Accept, Authorization, Content-Type, X-Redmine-API-Key, X-Redmine-Switch-User, X-Redmine-Nometa'

    # How long a browser may cache a preflight result, in seconds. Kept short
    # so that removing an origin from the settings takes effect quickly.
    MAX_AGE = '600'

    # Response headers a cross-origin caller may read on top of the CORS-safe
    # list. Location is the one header Redmine's API sets that a client needs
    # and cannot see by default: creating an issue or a project answers 201
    # with it and nothing else, so without this the create flow is only half
    # usable from a browser. Fixed, like the two lists above -- nothing is
    # reflected from the request.
    EXPOSED_HEADERS = 'Location'

    # An origin is a scheme, a host and an optional port, and nothing else
    # (RFC 6454 section 6.1). Anything that does not serialise that way -- a
    # path, a wildcard, the literal "null" -- is rejected here and can never
    # reach the comparison below.
    ORIGIN_FORMAT = %r{\Ahttps?://(?:\[[0-9a-f:.]+\]|[a-z0-9\-._~%]+)(?::\d{1,5})?\z}

    # Returns true when the API is enabled and at least one origin is allowed.
    def self.enabled?
      Setting.rest_api_enabled? && allowed_origins.any?
    end

    # Returns the configured origins, normalised. Entries that are not valid
    # origins are dropped rather than being matched loosely.
    #
    # The result is memoised against the raw setting string, because enabled?
    # and allows? both need it on every API request and splitting plus regex
    # matching the list twice per request is pure waste. Keying the memo on the
    # value it was derived from means there is nothing to invalidate: a changed
    # setting -- whether from the settings screen, from Setting.check_cache
    # picking up another process's write, or from a test -- produces a
    # different key and is recomputed. Two threads racing here compute the same
    # answer and assign the same kind of frozen pair, so the worst case is
    # duplicated work.
    def self.allowed_origins
      raw = Setting.rest_api_cors_origins.to_s
      cached = @allowed_origins
      return cached.last if cached && cached.first == raw

      origins = raw.split(',').filter_map {|value| normalize(value)}.freeze
      @allowed_origins = [raw, origins].freeze
      origins
    end

    # Returns true if the given Origin header value is allowed.
    #
    # The value that arrives on the wire is compared as it stands. It is not
    # normalised first: a browser always serialises an origin in canonical form
    # (RFC 6454 section 6.1), so anything else did not come from one and should
    # not be given the benefit of the doubt.
    #
    # The comparison is on whole strings, never on a prefix, a suffix or a
    # substring: "https://evil-example.com" and "https://example.com.evil.net"
    # must both fail a policy written for "https://example.com".
    def self.allows?(origin)
      origin = origin.to_s

      ORIGIN_FORMAT.match?(origin) && allowed_origins.include?(origin)
    end

    # Returns the value the Vary response header should take once a response is
    # known to depend on the request's Origin, preserving any fields that are
    # already there. Without this a shared cache can store the response given
    # to one origin and replay it to another.
    def self.vary_with_origin(current)
      fields = current.to_s.split(',').map(&:strip).reject(&:empty?)
      return current.to_s if fields.include?('*') || fields.any? {|field| field.casecmp?('Origin')}

      fields.push('Origin').join(', ')
    end

    # Returns the canonical form of a *configured* origin, or nil if the value
    # is not one.
    #
    # Only the cosmetic differences an administrator is likely to type are
    # smoothed over: surrounding whitespace, a trailing slash and letter case.
    # Nothing else is inferred -- in particular no default port is added or
    # removed, because "https://example.com" and "https://example.com:443" are
    # different Origin header values and only the first is ever sent.
    def self.normalize(value)
      value = value.to_s.strip.chomp('/').downcase

      value if ORIGIN_FORMAT.match?(value)
    end
  end
end
