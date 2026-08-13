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

class Redmine::ApiTest::EndpointControlTest < Redmine::ApiTest::Base
  fixtures :projects, :users, :email_addresses, :roles, :members, :member_roles,
           :issues, :issue_statuses, :versions, :trackers, :projects_trackers,
           :issue_categories, :enabled_modules, :enumerations, :attachments,
           :workflows, :custom_fields, :custom_values, :custom_fields_projects,
           :custom_fields_trackers, :time_entries, :journals, :journal_details,
           :queries, :attachments, :news

  def test_an_endpoint_should_answer_while_it_is_enabled
    get '/issues.json', :headers => credentials('jsmith')
    assert_response :ok
  end

  def test_a_disabled_endpoint_should_be_refused
    with_settings :rest_api_disabled_endpoints => ['issues#index'] do
      get '/issues.json', :headers => credentials('jsmith')
      assert_response :forbidden
    end
  end

  def test_disabling_one_endpoint_should_leave_its_siblings_alone
    with_settings :rest_api_disabled_endpoints => ['issues#index'] do
      get '/issues/1.json', :headers => credentials('jsmith')
      assert_response :ok
    end
  end

  def test_ep_007_an_endpoint_the_setting_has_never_seen_should_answer
    with_settings :rest_api_disabled_endpoints => ['issues#index'] do
      get '/news.json', :headers => credentials('jsmith')
      assert_response :ok
      get '/users/current.json', :headers => credentials('jsmith')
      assert_response :ok
    end
  end

  def test_ep_001_a_disabled_endpoint_should_be_refused_in_every_format
    with_settings :rest_api_disabled_endpoints => ['issues#index'] do
      get '/issues.json', :headers => credentials('jsmith')
      assert_response :forbidden
      get '/issues.xml', :headers => credentials('jsmith')
      assert_response :forbidden
      get '/issues.csv', :headers => credentials('jsmith')
      assert_response :forbidden
    end
  end

  def test_ep_002_a_disabled_endpoint_should_be_refused_through_a_nested_route
    # /projects/:id/issues.json reaches the same controller action by another
    # path. The gate keys on controller#action, never on the URL.
    with_settings :rest_api_disabled_endpoints => ['issues#index'] do
      get '/projects/ecookbook/issues.json', :headers => credentials('jsmith')
      assert_response :forbidden
    end
  end

  def test_ep_002_a_disabled_endpoint_should_be_refused_through_every_verb_that_reaches_it
    # PUT and PATCH both route to issues#update.
    with_settings :rest_api_disabled_endpoints => ['issues#update'] do
      put '/issues/1.json', :params => {:issue => {:subject => 'via put'}},
          :headers => credentials('jsmith')
      assert_response :forbidden

      patch '/issues/1.json', :params => {:issue => {:subject => 'via patch'}},
            :headers => credentials('jsmith')
      assert_response :forbidden

      assert_not_equal 'via put', Issue.find(1).subject
      assert_not_equal 'via patch', Issue.find(1).subject
    end
  end

  def test_ep_003_a_disabled_endpoint_should_be_refused_as_html_with_a_credential_in_a_header
    # accept_api_auth? has no format check, so a header credential authenticates
    # an accept_api_auth action even for an HTML request. Confirm that both
    # halves are true: the HTML request really does authenticate, and the gate
    # really does cover it.
    key = User.find_by_login('jsmith').api_key

    get '/my/account', :headers => {'X-Redmine-API-Key' => key}
    assert_response :ok

    with_settings :rest_api_disabled_endpoints => ['my#account'] do
      get '/my/account', :headers => {'X-Redmine-API-Key' => key}
      assert_response :forbidden
    end
  end

  def test_ep_003_a_disabled_endpoint_should_be_refused_as_html_with_a_personal_access_token
    user = User.find_by_login('jsmith')
    token = PersonalAccessToken.create!(:user => user, :name => 'CI')

    with_settings :rest_api_disabled_endpoints => ['my#account'] do
      get '/my/account', :headers => {'X-Redmine-API-Key' => token.value}
      assert_response :forbidden
    end
  end

  def test_ep_010_a_disabled_endpoint_should_not_change_the_html_interface
    # A human browsing with a session cookie never enters the API branch of
    # find_current_user, so the gate must not touch them.
    log_user('jsmith', 'jsmith')

    with_settings :rest_api_disabled_endpoints => ['issues#index', 'my#account', 'projects#index'] do
      get '/issues'
      assert_response :ok
      get '/my/account'
      assert_response :ok
      get '/projects'
      assert_response :ok
    end
  end

  def test_ep_010_a_session_should_not_be_gated_even_when_the_request_also_carries_a_credential
    log_user('jsmith', 'jsmith')
    key = User.find_by_login('jsmith').api_key

    with_settings :rest_api_disabled_endpoints => ['my#account'] do
      # The session authenticates first and the header is never read, so this
      # is a browser request and stays one.
      get '/my/account', :headers => {'X-Redmine-API-Key' => key}
      assert_response :ok
    end
  end

  def test_ep_009_a_disabled_write_endpoint_should_not_write
    with_settings :rest_api_disabled_endpoints => ['issues#create'] do
      assert_no_difference 'Issue.count' do
        post '/issues.json',
             :params => {:issue => {:project_id => 1, :subject => 'created through a disabled endpoint'}},
             :headers => credentials('jsmith')
      end
      assert_response :forbidden
    end
  end

  def test_ep_009_a_disabled_delete_endpoint_should_not_delete
    with_settings :rest_api_disabled_endpoints => ['issues#destroy'] do
      assert_no_difference 'Issue.count' do
        delete '/issues/1.json', :headers => credentials('admin')
      end
      assert_response :forbidden
    end
  end

  def test_ep_008_the_gate_should_apply_to_the_api_key_in_a_query_parameter
    key = User.find_by_login('jsmith').api_key

    with_settings :rest_api_disabled_endpoints => ['issues#index'] do
      get "/issues.json?key=#{key}"
      assert_response :forbidden
    end
  end

  def test_ep_008_the_gate_should_apply_to_a_personal_access_token
    user = User.find_by_login('jsmith')
    token = PersonalAccessToken.create!(:user => user, :name => 'CI')

    get '/issues.json', :headers => {'X-Redmine-API-Key' => token.value}
    assert_response :ok

    with_settings :rest_api_disabled_endpoints => ['issues#index'] do
      get '/issues.json', :headers => {'X-Redmine-API-Key' => token.value}
      assert_response :forbidden
    end
  end

  def test_ep_008_the_gate_should_apply_to_http_basic_credentials
    with_settings :rest_api_disabled_endpoints => ['issues#index'] do
      get '/issues.json', :headers => credentials('jsmith', 'jsmith')
      assert_response :forbidden

      key = User.find_by_login('jsmith').api_key
      get '/issues.json', :headers => credentials(key, 'X')
      assert_response :forbidden
    end
  end

  def test_ep_008_the_gate_should_apply_to_an_oauth_token
    application = Doorkeeper::Application.create!(
      :name => 'endpoint control test', :redirect_uri => 'urn:ietf:wg:oauth:2.0:oob',
      :scopes => 'view_issues'
    )
    token = Doorkeeper::AccessToken.create!(
      :application => application, :resource_owner_id => 2, :scopes => 'view_issues'
    )
    headers = {'HTTP_AUTHORIZATION' => "Bearer #{token.plaintext_token}"}

    get '/issues.json', :headers => headers
    assert_response :ok

    with_settings :rest_api_disabled_endpoints => ['issues#index'] do
      get '/issues.json', :headers => headers
      assert_response :forbidden
    end
  end

  def test_ep_008_the_gate_should_apply_after_a_switch_user_header
    key = User.find_by_login('admin').api_key
    headers = {'X-Redmine-API-Key' => key, 'X-Redmine-Switch-User' => 'jsmith'}

    get '/issues.json', :headers => headers
    assert_response :ok

    with_settings :rest_api_disabled_endpoints => ['issues#index'] do
      get '/issues.json', :headers => headers
      assert_response :forbidden
    end
  end

  def test_ep_008_the_gate_should_apply_to_an_administrator
    # An administrator is a caller, not an exception. There is no bypass.
    with_settings :rest_api_disabled_endpoints => ['users#index'] do
      get '/users.json', :headers => credentials('admin')
      assert_response :forbidden
    end
  end

  def test_ep_004_the_refusal_should_look_like_the_rest_api_being_switched_off
    # A caller must not be able to tell "this endpoint is disabled" from "the
    # API is not available to you", or the configuration becomes readable by
    # anyone who can send a request.
    disabled_endpoint = nil
    disabled_api = nil

    with_settings :rest_api_disabled_endpoints => ['issues#index'] do
      get '/issues.json', :headers => credentials('jsmith')
      assert_response :forbidden
      disabled_endpoint = [response.code, response.body, response.headers['Content-Type']]
    end

    with_settings :rest_api_enabled => '0', :login_required => '1' do
      get '/issues.json', :headers => credentials('jsmith')
      assert_response :forbidden
      disabled_api = [response.code, response.body, response.headers['Content-Type']]
    end

    assert_equal disabled_api, disabled_endpoint
    assert_equal '', disabled_endpoint[1]
  end

  def test_ep_005_disabling_every_endpoint_should_not_lock_the_administrator_out
    # The screen that re-enables endpoints is an HTML administration screen and
    # declares no accept_api_auth, so it can never be one of the endpoints this
    # feature switches off.
    log_user('admin', 'admin')

    with_settings :rest_api_disabled_endpoints => Redmine::ApiEndpoints.all do
      get '/settings', :params => {:tab => 'api'}
      assert_response :ok
      assert_select 'input[name=?]', 'settings[rest_api_disabled_endpoints][issues#index]'

      post '/settings/edit', :params => {
        :tab => 'api',
        :settings => {:rest_api_disabled_endpoints => {'issues#index' => '0'}}
      }
      assert_response :redirect
    end

    assert_equal [], Setting.rest_api_disabled_endpoints
  ensure
    Setting.rest_api_disabled_endpoints = []
  end

  def test_ep_011_a_disabled_endpoint_should_not_be_reachable_with_a_format_query_parameter
    # api_request? reads params[:format], which a caller can supply on any
    # route. That can only ever make the gate apply to more requests, never to
    # fewer -- confirm it, because the CORS pillar had the mirror-image bug.
    with_settings :rest_api_disabled_endpoints => ['issues#index'] do
      get '/issues?format=json', :headers => credentials('jsmith')
      assert_response :forbidden
    end
  end

  def test_an_anonymous_html_request_to_a_disabled_endpoint_should_behave_as_before
    with_settings :rest_api_disabled_endpoints => ['issues#index'] do
      get '/issues'
      assert_response :ok
    end
  end

  def test_ep_r11_the_default_configuration_should_change_nothing
    assert_equal [], Setting.rest_api_disabled_endpoints

    get '/issues.json', :headers => credentials('jsmith')
    assert_response :ok
    get '/issues.xml', :headers => credentials('jsmith')
    assert_response :ok
    post '/issues.json',
         :params => {:issue => {:project_id => 1, :subject => 'still fine'}},
         :headers => credentials('jsmith')
    assert_response :created
  end
end
