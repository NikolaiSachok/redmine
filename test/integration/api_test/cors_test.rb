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

require_relative '../../test_helper'

# Cross-origin resource sharing for the REST API.
#
# These go through the full Rack stack on purpose: the value of a CORS policy
# is entirely in the response headers a browser will see, and a controller unit
# test would not exercise the routing, the filter order or the error paths.
class Redmine::ApiTest::CorsTest < Redmine::ApiTest::Base
  ALLOWED = 'https://app.example.com'

  def teardown
    super
    Setting.rest_api_cors_origins = ''
  end

  # CORS-R9, CORS-R12, CORS-008: off by default.
  def test_no_cors_headers_should_be_sent_by_default
    assert_equal '', Setting.rest_api_cors_origins

    get '/issues.json', :headers => {'HTTP_ORIGIN' => ALLOWED}.merge(credentials('jsmith'))

    assert_response :success
    assert_nil response.headers['Access-Control-Allow-Origin']
    assert_not_includes vary_fields, 'origin'
  end

  # CORS-008: an empty list means allow nothing, and so does a list that only
  # contains separators or blanks.
  def test_blank_origins_list_should_allow_nothing
    ['', '  ', ',', ' , , '].each do |value|
      Setting.rest_api_cors_origins = value

      get '/issues.json', :headers => {'HTTP_ORIGIN' => ALLOWED}.merge(credentials('jsmith'))

      assert_response :success
      assert_nil response.headers['Access-Control-Allow-Origin'], "#{value.inspect} enabled CORS"
    end
  end

  # CORS-R1, CORS-R3.
  def test_allowed_origin_should_receive_the_header
    Setting.rest_api_cors_origins = ALLOWED

    get '/issues.json', :headers => {'HTTP_ORIGIN' => ALLOWED}.merge(credentials('jsmith'))

    assert_response :success
    assert_equal ALLOWED, response.headers['Access-Control-Allow-Origin']
  end

  def test_several_origins_may_be_configured
    Setting.rest_api_cors_origins = "https://a.example.com, https://b.example.com , https://c.example.com/"

    ['https://a.example.com', 'https://b.example.com', 'https://c.example.com'].each do |origin|
      get '/issues.json', :headers => {'HTTP_ORIGIN' => origin}.merge(credentials('jsmith'))

      assert_response :success
      assert_equal origin, response.headers['Access-Control-Allow-Origin']
    end
  end

  def test_configured_origin_should_be_matched_regardless_of_case_and_trailing_slash
    Setting.rest_api_cors_origins = 'HTTPS://APP.EXAMPLE.COM/'

    get '/issues.json', :headers => {'HTTP_ORIGIN' => ALLOWED}.merge(credentials('jsmith'))

    assert_response :success
    assert_equal ALLOWED, response.headers['Access-Control-Allow-Origin']
  end

  # CORS-R4, CORS-001: an arbitrary origin is never reflected.
  def test_disallowed_origin_should_receive_no_allow_origin_header
    Setting.rest_api_cors_origins = ALLOWED

    get '/issues.json', :headers => {'HTTP_ORIGIN' => 'https://evil.example'}.merge(credentials('jsmith'))

    assert_response :success
    assert_nil response.headers['Access-Control-Allow-Origin']
  end

  # CORS-R5, CORS-003: exact matching on scheme, host and port.
  def test_origin_matching_should_be_exact
    Setting.rest_api_cors_origins = ALLOWED

    [
      'http://app.example.com',           # different scheme
      'https://app.example.com:8443',     # different port
      'https://evil-app.example.com',     # prefix on the host
      'https://app.example.com.evil.net', # suffix on the host
      'https://xapp.example.com',
      'https://app.example.como',
      'https://app.example.com/',         # not a valid Origin serialisation
      'https://app.example.com#',
      'https://app.example.com https://app.example.com',
      'app.example.com',
      '*'
    ].each do |origin|
      get '/issues.json', :headers => {'HTTP_ORIGIN' => origin}.merge(credentials('jsmith'))

      assert_response :success
      assert_nil response.headers['Access-Control-Allow-Origin'], "#{origin} was allowed"
    end
  end

  # CORS-R6, CORS-004: null is never allowed, not even if an administrator
  # types it into the setting.
  def test_null_origin_should_never_be_allowed
    ['null', "#{ALLOWED}, null"].each do |setting|
      Setting.rest_api_cors_origins = setting

      get '/issues.json', :headers => {'HTTP_ORIGIN' => 'null'}.merge(credentials('jsmith'))

      assert_response :success
      assert_nil response.headers['Access-Control-Allow-Origin'], "null was allowed with #{setting.inspect}"
    end
  end

  # CORS-008: a wildcard in the setting allows nothing rather than everything.
  def test_wildcard_in_the_setting_should_allow_nothing
    Setting.rest_api_cors_origins = '*'

    get '/issues.json', :headers => {'HTTP_ORIGIN' => 'https://evil.example'}.merge(credentials('jsmith'))

    assert_response :success
    assert_nil response.headers['Access-Control-Allow-Origin']

    options '/issues.json', :headers => {
      'HTTP_ORIGIN' => 'https://evil.example',
      'HTTP_ACCESS_CONTROL_REQUEST_METHOD' => 'GET'
    }
    assert_response :not_found
  end

  # CORS-002: credentials are never advertised, so an echoed origin can never
  # be combined with the session cookie.
  def test_allow_credentials_should_never_be_sent
    Setting.rest_api_cors_origins = ALLOWED

    get '/issues.json', :headers => {'HTTP_ORIGIN' => ALLOWED}.merge(credentials('jsmith'))
    assert_response :success
    assert_nil response.headers['Access-Control-Allow-Credentials']

    options '/issues.json', :headers => {
      'HTTP_ORIGIN' => ALLOWED,
      'HTTP_ACCESS_CONTROL_REQUEST_METHOD' => 'GET'
    }
    assert_response :no_content
    assert_nil response.headers['Access-Control-Allow-Credentials']
  end

  # CORS-R8, CORS-007: the response varies by origin whether or not the origin
  # was allowed, so a shared cache cannot cross-serve.
  def test_vary_origin_should_be_sent_while_the_feature_is_on
    Setting.rest_api_cors_origins = ALLOWED

    [ALLOWED, 'https://evil.example', nil].each do |origin|
      headers = credentials('jsmith')
      headers = headers.merge('HTTP_ORIGIN' => origin) if origin

      get '/issues.json', :headers => headers

      assert_response :success
      assert_includes vary_fields, 'origin', "Vary: Origin missing for #{origin.inspect}"
    end
  end

  # CORS-R10, CORS-006: HTML responses never carry the headers.
  def test_html_responses_should_never_carry_cors_headers
    Setting.rest_api_cors_origins = ALLOWED

    get '/login', :headers => {'HTTP_ORIGIN' => ALLOWED}
    assert_response :success
    assert_nil response.headers['Access-Control-Allow-Origin']
    assert_not_includes vary_fields, 'origin'

    get '/issues', :headers => {'HTTP_ORIGIN' => ALLOWED}
    assert_response :success
    assert_nil response.headers['Access-Control-Allow-Origin']
    assert_not_includes vary_fields, 'origin'
  end

  # CORS-R12: with the REST API disabled the feature is inert even if origins
  # are configured.
  def test_nothing_should_be_sent_when_the_rest_api_is_disabled
    Setting.rest_api_cors_origins = ALLOWED
    Setting.rest_api_enabled = '0'

    get '/issues.json', :headers => {'HTTP_ORIGIN' => ALLOWED}.merge(credentials('jsmith'))
    assert_response :success
    assert_nil response.headers['Access-Control-Allow-Origin']
    assert_not_includes vary_fields, 'origin'
  end

  # CORS-R7: a preflight is answered for an allowed origin.
  def test_preflight_should_be_answered_for_an_allowed_origin
    Setting.rest_api_cors_origins = ALLOWED

    options '/issues.json', :headers => {
      'HTTP_ORIGIN' => ALLOWED,
      'HTTP_ACCESS_CONTROL_REQUEST_METHOD' => 'GET',
      'HTTP_ACCESS_CONTROL_REQUEST_HEADERS' => 'x-redmine-api-key'
    }

    assert_response :no_content
    assert_equal '', response.body
    assert_equal ALLOWED, response.headers['Access-Control-Allow-Origin']
    assert_equal Redmine::Cors::ALLOWED_METHODS, response.headers['Access-Control-Allow-Methods']
    assert_equal Redmine::Cors::ALLOWED_HEADERS, response.headers['Access-Control-Allow-Headers']
    assert_equal Redmine::Cors::MAX_AGE, response.headers['Access-Control-Max-Age']
    assert_includes vary_fields, 'origin'
  end

  # A preflight carries no credentials, so it must not be turned away by the
  # login requirement -- and it must not become an unauthenticated read of
  # anything either, which is why the body is empty.
  def test_preflight_should_not_require_authentication
    Setting.rest_api_cors_origins = ALLOWED

    with_settings :login_required => '1' do
      options '/issues.json', :headers => {
        'HTTP_ORIGIN' => ALLOWED,
        'HTTP_ACCESS_CONTROL_REQUEST_METHOD' => 'GET'
      }
    end

    assert_response :no_content
    assert_equal '', response.body
  end

  # CORS-005: the preflight answer is the same for every path, so it discloses
  # neither which resources exist nor which ones the caller could read.
  def test_preflight_should_not_disclose_whether_the_resource_exists
    Setting.rest_api_cors_origins = ALLOWED
    headers = {'HTTP_ORIGIN' => ALLOWED, 'HTTP_ACCESS_CONTROL_REQUEST_METHOD' => 'GET'}

    responses = ['/issues/1.json', '/issues/999999.json', '/no/such/thing.json'].map do |path|
      options path, :headers => headers
      [response.status, response.body, response.headers['Access-Control-Allow-Origin']]
    end

    assert_equal 1, responses.uniq.size, "preflight answers differed: #{responses.inspect}"
    assert_equal [204, '', ALLOWED], responses.first
  end

  # CORS-R7: no preflight answer for an origin that is not allowed. The route
  # behaves as it did before the feature existed.
  def test_preflight_should_be_refused_for_a_disallowed_origin
    Setting.rest_api_cors_origins = ALLOWED

    options '/issues.json', :headers => {
      'HTTP_ORIGIN' => 'https://evil.example',
      'HTTP_ACCESS_CONTROL_REQUEST_METHOD' => 'GET'
    }

    assert_response :not_found
    assert_nil response.headers['Access-Control-Allow-Origin']
    assert_nil response.headers['Access-Control-Allow-Methods']
  end

  # CORS-005: the preflight route does not bypass the rest_api_enabled gate.
  def test_preflight_should_be_refused_when_the_rest_api_is_disabled
    Setting.rest_api_cors_origins = ALLOWED
    Setting.rest_api_enabled = '0'

    options '/issues.json', :headers => {
      'HTTP_ORIGIN' => ALLOWED,
      'HTTP_ACCESS_CONTROL_REQUEST_METHOD' => 'GET'
    }

    assert_response :not_found
    assert_nil response.headers['Access-Control-Allow-Origin']
  end

  # CORS-R12: OPTIONS on a non-API path still 404s, and OPTIONS anywhere 404s
  # while the feature is off. Both are what Redmine did before.
  def test_options_should_behave_as_before_outside_the_api
    Setting.rest_api_cors_origins = ALLOWED

    options '/issues', :headers => {'HTTP_ORIGIN' => ALLOWED}
    assert_response :not_found
    assert_nil response.headers['Access-Control-Allow-Origin']

    Setting.rest_api_cors_origins = ''
    options '/issues.json', :headers => {'HTTP_ORIGIN' => ALLOWED}
    assert_response :not_found
  end

  # CORS-006 read the other way: an allowed origin does get the header on an
  # API error response, deliberately, so that a browser client can see the 401
  # instead of an opaque network failure.
  def test_allowed_origin_should_receive_the_header_on_an_authentication_failure
    Setting.rest_api_cors_origins = ALLOWED

    get '/my/account.json', :headers => {'HTTP_ORIGIN' => ALLOWED}.merge(credentials('jsmith', 'wrong'))

    assert_response :unauthorized
    assert_equal ALLOWED, response.headers['Access-Control-Allow-Origin']

    get '/users.json', :headers => {'HTTP_ORIGIN' => ALLOWED}.merge(credentials('jsmith'))

    assert_response :forbidden
    assert_equal ALLOWED, response.headers['Access-Control-Allow-Origin']
  end

  def test_disallowed_origin_should_receive_nothing_on_an_error_response
    Setting.rest_api_cors_origins = ALLOWED

    get '/my/account.json', :headers => {'HTTP_ORIGIN' => 'https://evil.example'}.merge(credentials('jsmith', 'wrong'))

    assert_response :unauthorized
    assert_nil response.headers['Access-Control-Allow-Origin']
  end

  # An allowed origin still has to authenticate: the header grants a browser
  # permission to read a response, never permission to make the request.
  def test_allowed_origin_should_not_be_a_credential
    Setting.rest_api_cors_origins = ALLOWED

    get '/users.json', :headers => {'HTTP_ORIGIN' => ALLOWED}

    assert_response :unauthorized
  end

  private

  def vary_fields
    response.headers['Vary'].to_s.split(',').map {|f| f.strip.downcase}
  end
end
