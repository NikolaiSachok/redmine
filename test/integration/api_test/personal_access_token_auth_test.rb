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

class Redmine::ApiTest::PersonalAccessTokenAuthTest < Redmine::ApiTest::Base
  def test_should_accept_a_token_as_request_header
    user = User.generate!
    token = PersonalAccessToken.create!(:user => user, :name => 'CI')

    get '/users/current.json', :headers => {'X-Redmine-API-Key' => token.value}
    assert_response :ok
    assert_equal user.id, ActiveSupport::JSON.decode(response.body)['user']['id']
  end

  def test_should_accept_a_token_as_http_basic_username
    user = User.generate!
    token = PersonalAccessToken.create!(:user => user, :name => 'CI')

    get '/users/current.json', :headers => credentials(token.value, 'X')
    assert_response :ok
  end

  def test_should_not_accept_a_token_as_query_parameter
    user = User.generate!
    token = PersonalAccessToken.create!(:user => user, :name => 'CI')

    # Request parameters are written to the application log, so a personal
    # access token is deliberately not accepted from the query string.
    get "/users/current.json?key=#{token.value}"
    assert_response :unauthorized
  end

  def test_an_api_key_parameter_should_still_win_over_a_token_header
    user = User.generate!
    api_key = user.api_key

    # a client migrating from the API key may carry both; the API key keeps
    # authenticating exactly as it did before personal access tokens existed
    get "/users/current.json?key=#{api_key}",
        :headers => {'X-Redmine-API-Key' => "rmpat_#{Redmine::Utils.random_hex(20)}"}
    assert_response :ok
  end

  def test_a_token_header_should_be_used_when_the_api_key_parameter_is_invalid
    user = User.generate!
    token = PersonalAccessToken.create!(:user => user, :name => 'CI')

    get '/users/current.json?key=0000000000000000000000000000000000000000',
        :headers => {'X-Redmine-API-Key' => token.value}
    assert_response :ok
    assert_equal user.id, ActiveSupport::JSON.decode(response.body)['user']['id']
  end

  def test_should_deny_an_unknown_token
    get '/users/current.json',
        :headers => {'X-Redmine-API-Key' => "rmpat_#{Redmine::Utils.random_hex(20)}"}
    assert_response :unauthorized
  end

  def test_should_deny_a_revoked_token
    user = User.generate!
    token = PersonalAccessToken.create!(:user => user, :name => 'CI')
    value = token.value

    get '/users/current.json', :headers => {'X-Redmine-API-Key' => value}
    assert_response :ok

    token.destroy
    get '/users/current.json', :headers => {'X-Redmine-API-Key' => value}
    assert_response :unauthorized
  end

  def test_should_deny_an_expired_token
    user = User.generate!
    token = PersonalAccessToken.create!(:user => user, :name => 'CI')
    token.update_column(:expires_on, User.current.today - 1)

    get '/users/current.json', :headers => {'X-Redmine-API-Key' => token.value}
    assert_response :unauthorized
  end

  def test_should_deny_a_locked_user_and_accept_again_once_unlocked
    user = User.generate!
    token = PersonalAccessToken.create!(:user => user, :name => 'CI')

    user.update_columns(:status => User::STATUS_LOCKED)
    get '/users/current.json', :headers => {'X-Redmine-API-Key' => token.value}
    assert_response :unauthorized

    user.update_columns(:status => User::STATUS_ACTIVE)
    get '/users/current.json', :headers => {'X-Redmine-API-Key' => token.value}
    assert_response :ok
  end

  def test_should_deny_a_token_when_the_rest_api_is_disabled
    user = User.generate!
    token = PersonalAccessToken.create!(:user => user, :name => 'CI')

    with_settings :rest_api_enabled => '0' do
      get '/users/current.json', :headers => {'X-Redmine-API-Key' => token.value}
      # same response as the existing API key gets when the API is disabled,
      # see test/integration/api_test/disabled_rest_api_test.rb
      assert_response :forbidden
    end
  end

  def test_should_record_the_use
    user = User.generate!
    token = PersonalAccessToken.create!(:user => user, :name => 'CI')
    assert_nil token.last_used_on

    get '/users/current.json', :headers => {'X-Redmine-API-Key' => token.value}
    assert_response :ok
    assert_not_nil token.reload.last_used_on
  end

  def test_a_user_may_authenticate_with_several_tokens
    user = User.generate!
    first = PersonalAccessToken.create!(:user => user, :name => 'laptop')
    second = PersonalAccessToken.create!(:user => user, :name => 'CI')

    # unlike the API key, issuing a second token does not invalidate the first
    [first, second].each do |token|
      get '/users/current.json', :headers => {'X-Redmine-API-Key' => token.value}
      assert_response :ok
    end
  end

  # ATTACKS.md PAT-002: a token that expires and can be revoked must not be
  # tradeable for the permanent, unscoped API key.
  def test_pat_002_a_token_must_not_disclose_the_api_key
    user = User.generate!
    user.api_key
    token = PersonalAccessToken.create!(:user => user, :name => 'CI')

    get '/my/account.json', :headers => {'X-Redmine-API-Key' => token.value}
    assert_response :ok
    assert_nil ActiveSupport::JSON.decode(response.body)['user']['api_key']

    get '/users/current.json', :headers => {'X-Redmine-API-Key' => token.value}
    assert_response :ok
    assert_nil ActiveSupport::JSON.decode(response.body)['user']['api_key']
  end

  def test_pat_002_the_api_key_is_still_disclosed_to_its_own_holder
    user = User.generate!
    api_key = user.api_key

    # unchanged for the legacy credential: only the token path is restricted
    get '/my/account.json', :headers => {'X-Redmine-API-Key' => api_key}
    assert_response :ok
    assert_equal api_key, ActiveSupport::JSON.decode(response.body)['user']['api_key']
  end

  # ATTACKS.md PAT-007: a token mistakenly sent as ?key= does not authenticate,
  # but it must not be written to the log in cleartext either.
  # ATTACKS.md PAT-002: impersonation loads a fresh user record, so the
  # restriction has to be carried over or it stops applying mid-request.
  def test_pat_002_switching_user_must_not_disclose_the_api_key
    admin = User.find(1)
    token = PersonalAccessToken.create!(:user => admin, :name => 'CI')
    target = User.find(2)
    target.api_key

    get '/users/current.json',
        :headers => {'X-Redmine-API-Key' => token.value,
                     'X-Redmine-Switch-User' => target.login}
    assert_response :ok
    json = ActiveSupport::JSON.decode(response.body)['user']
    assert_equal target.id, json['id']
    assert_nil json['api_key']
  end

  def test_switching_user_with_an_api_key_is_unchanged
    admin = User.find(1)
    api_key = admin.api_key
    target = User.find(2)
    target_key = target.api_key

    # the legacy credential keeps its existing behaviour, restriction or not
    get '/users/current.json',
        :headers => {'X-Redmine-API-Key' => api_key,
                     'X-Redmine-Switch-User' => target.login}
    assert_response :ok
    assert_equal target_key, ActiveSupport::JSON.decode(response.body)['user']['api_key']
  end

  def test_pat_007_a_credential_parameter_is_filtered_from_logs
    filtered = ActiveSupport::ParameterFilter
               .new(Rails.application.config.filter_parameters)
               .filter('key' => "rmpat_#{Redmine::Utils.random_hex(20)}")
    assert_equal '[FILTERED]', filtered['key']
  end

  def test_the_existing_api_key_should_still_authenticate_alongside_tokens
    user = User.generate!
    api_key = user.api_key
    PersonalAccessToken.create!(:user => user, :name => 'CI')

    # all three transports of the existing API key are untouched
    get '/users/current.json', :headers => {'X-Redmine-API-Key' => api_key}
    assert_response :ok

    get "/users/current.json?key=#{api_key}"
    assert_response :ok

    get '/users/current.json', :headers => credentials(api_key, 'X')
    assert_response :ok
  end
end
