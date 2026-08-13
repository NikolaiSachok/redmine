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

  def setup
    super
    set_fixtures_attachments_directory
  end

  def teardown
    super
    set_tmp_attachments_directory
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
  # neither which resources exist nor which ones the caller could read. The
  # third path in each group is the one the caller would be *forbidden* from
  # reading -- /users.json is administrators only and /issues/4.json is in a
  # private project -- and it has to be indistinguishable from the rest.
  def test_preflight_should_not_disclose_whether_the_resource_exists_or_is_permitted
    Setting.rest_api_cors_origins = ALLOWED
    headers = {'HTTP_ORIGIN' => ALLOWED, 'HTTP_ACCESS_CONTROL_REQUEST_METHOD' => 'GET'}
    paths = [
      '/issues/1.json',      # exists and is readable
      '/issues/999999.json', # does not exist
      '/no/such/thing.json', # not even a route
      '/users.json',         # exists, but anonymous would get 401/403
      '/issues/4.json',      # exists, in a project this caller cannot see
      '/admin.json'          # administration
    ]

    responses = paths.map do |path|
      options path, :headers => headers
      [
        response.status,
        response.body,
        response.headers['Access-Control-Allow-Origin'],
        response.headers['Access-Control-Allow-Methods'],
        response.headers['Access-Control-Allow-Headers'],
        response.headers['Access-Control-Max-Age'],
        response.headers['Set-Cookie']
      ]
    end

    assert_equal 1, responses.uniq.size, "preflight answers differed: #{responses.inspect}"
    assert_equal(
      [204, '', ALLOWED, Redmine::Cors::ALLOWED_METHODS, Redmine::Cors::ALLOWED_HEADERS,
       Redmine::Cors::MAX_AGE, nil],
      responses.first
    )
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

  # CORS-010, from the attack ledger. api_request? is true whenever
  # params[:format] is json or xml, and that can be supplied as a query
  # parameter on any route at all -- so before the filter was narrowed to the
  # format the *route* resolved, a caller could opt a plain file download into
  # the CORS policy and read the raw bytes cross-origin. The response is a
  # normal successful download; only the CORS headers must be absent.
  def test_cors_010_a_format_query_parameter_must_not_put_cors_headers_on_a_file_download
    Setting.rest_api_cors_origins = ALLOWED

    get '/attachments/download/4?format=json', :headers => {'HTTP_ORIGIN' => ALLOWED}.merge(credentials('jsmith'))

    assert_response :success
    assert_equal 'This is a Ruby source file', Attachment.find(4).description
    assert_includes response.body, 'class'
    assert_nil response.headers['Access-Control-Allow-Origin']
    assert_nil response.headers['Access-Control-Expose-Headers']
    assert_not_includes vary_fields, 'origin'
  end

  # CORS-006, the same trick on HTML routes. These answer 403 or a redirect
  # rather than a body worth stealing, but a policy whose scope the caller
  # chooses is not a policy.
  def test_cors_006_a_format_query_parameter_must_not_put_cors_headers_on_an_html_route
    Setting.rest_api_cors_origins = ALLOWED

    ['/admin?format=json', '/settings?format=json', '/my/page?format=xml', '/issues?format=json'].each do |path|
      get path, :headers => {'HTTP_ORIGIN' => ALLOWED}.merge(credentials('jsmith'))

      assert_nil response.headers['Access-Control-Allow-Origin'], "#{path} carried Access-Control-Allow-Origin"
      assert_not_includes vary_fields, 'origin', "#{path} carried Vary: Origin"
    end
  end

  # CORS-014, from the attack ledger. This pins a precondition of the whole
  # design rather than any line of CORS code: find_current_user skips the
  # session entirely when api_request?, so a cross-origin request cannot be
  # authorised by the browser's cookie no matter what the CORS headers say.
  # That is why Access-Control-Allow-Credentials is never needed, and why
  # echoing an allowed origin is safe. If this ever stops holding, the CORS
  # policy becomes a session-riding hole.
  def test_cors_014_an_api_format_request_never_authenticates_from_the_session
    Setting.rest_api_cors_origins = ALLOWED
    log_user('jsmith', 'jsmith')

    # Same session, same cookie jar: the HTML page is authenticated...
    get '/my/account', :headers => {'HTTP_ORIGIN' => ALLOWED}
    assert_response :success

    # ...and the API representation of the very same resource is not.
    get '/my/account.json', :headers => {'HTTP_ORIGIN' => ALLOWED}
    assert_response :unauthorized

    get '/users/current.json', :headers => {'HTTP_ORIGIN' => ALLOWED}
    assert_response :unauthorized
  end

  # The reason the filter is prepended. These three refusals are rendered
  # inside user_setup itself, which halts the filter chain; a filter running
  # after it would never set the headers, and a browser client would see an
  # opaque network error instead of the 401 or 403 telling it what is wrong.
  def test_allowed_origin_should_receive_the_header_on_a_refusal_rendered_in_user_setup
    Setting.rest_api_cors_origins = ALLOWED

    # HTTP Basic while two-factor authentication is active -> 401.
    twofa_user = User.generate! do |user|
      user.password = 'my_password'
      user.update(:twofa_scheme => 'totp')
    end
    get '/users/current.json',
        :headers => {'HTTP_ORIGIN' => ALLOWED}.merge(credentials(twofa_user.login, 'my_password'))
    assert_response :unauthorized
    assert_equal ALLOWED, response.headers['Access-Control-Allow-Origin']
    assert_includes vary_fields, 'origin'

    # A password that must be changed before anything else -> 403.
    pwd_user = User.generate! do |user|
      user.password = 'my_password'
      user.must_change_passwd = true
    end
    get '/users/current.json',
        :headers => {'HTTP_ORIGIN' => ALLOWED}.merge(credentials(pwd_user.login, 'my_password'))
    assert_response :forbidden
    assert_equal ALLOWED, response.headers['Access-Control-Allow-Origin']

    # A revoked OAuth token -> doorkeeper_render_error, also inside user_setup.
    application = Doorkeeper::Application.create!(
      :name => 'cors test', :redirect_uri => 'urn:ietf:wg:oauth:2.0:oob', :scopes => 'view_issues'
    )
    token = Doorkeeper::AccessToken.create!(
      :application => application, :resource_owner_id => 2, :scopes => 'view_issues'
    )
    token.revoke
    get '/users/current.json',
        :headers => {'HTTP_ORIGIN' => ALLOWED, 'HTTP_AUTHORIZATION' => "Bearer #{token.plaintext_token}"}
    assert_response :unauthorized
    assert_equal ALLOWED, response.headers['Access-Control-Allow-Origin']
  end

  def test_disallowed_origin_should_receive_nothing_on_a_refusal_rendered_in_user_setup
    Setting.rest_api_cors_origins = ALLOWED
    user = User.generate! do |u|
      u.password = 'my_password'
      u.update(:twofa_scheme => 'totp')
    end

    get '/users/current.json',
        :headers => {'HTTP_ORIGIN' => 'https://evil.example'}.merge(credentials(user.login, 'my_password'))

    assert_response :unauthorized
    assert_nil response.headers['Access-Control-Allow-Origin']
  end

  # Creating a resource answers 201 with the new URL in Location, and a browser
  # cannot read that header cross-origin unless it is named in
  # Access-Control-Expose-Headers.
  def test_expose_headers_should_let_a_browser_read_location_on_a_created_resource
    Setting.rest_api_cors_origins = ALLOWED

    post '/issues.json',
         :params => {:issue => {:project_id => 1, :subject => 'CORS', :tracker_id => 1}},
         :headers => {'HTTP_ORIGIN' => ALLOWED}.merge(credentials('jsmith'))

    assert_response :created
    assert response.headers['Location'].present?
    assert_equal ALLOWED, response.headers['Access-Control-Allow-Origin']
    assert_equal 'Location', response.headers['Access-Control-Expose-Headers']
  end

  def test_expose_headers_should_not_be_sent_to_a_disallowed_origin
    Setting.rest_api_cors_origins = ALLOWED

    get '/issues.json', :headers => {'HTTP_ORIGIN' => 'https://evil.example'}.merge(credentials('jsmith'))

    assert_response :success
    assert_nil response.headers['Access-Control-Expose-Headers']
  end

  # The filter is prepended, so it runs before user_setup calls
  # Setting.check_cache. It therefore refreshes the settings cache itself --
  # without that, a change made in another process (which is what the settings
  # screen is, relative to this one) would only take effect on the request
  # after next, and an origin that had just been removed would still be served
  # once. update_all writes the row the way another process would: straight to
  # the database, leaving this process's cache stale.
  def test_a_settings_change_made_elsewhere_should_take_effect_on_the_very_next_request
    Setting.rest_api_cors_origins = ''
    assert_equal '', Setting.rest_api_cors_origins # warm the cache the way a served request would
    Setting.where(:name => 'rest_api_cors_origins').update_all(:value => ALLOWED, :updated_on => 1.second.from_now)
    assert_equal '', Setting.rest_api_cors_origins, 'the cache was not stale, so this test proves nothing'

    get '/issues.json', :headers => {'HTTP_ORIGIN' => ALLOWED}.merge(credentials('jsmith'))

    assert_response :success
    assert_equal ALLOWED, response.headers['Access-Control-Allow-Origin']
  end

  private

  def vary_fields
    response.headers['Vary'].to_s.split(',').map {|f| f.strip.downcase}
  end
end
