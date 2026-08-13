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

class Redmine::ApiTest::ApiAuditTest < Redmine::ApiTest::Base
  fixtures :projects, :users, :email_addresses, :roles, :members, :member_roles,
           :issues, :issue_statuses, :versions, :trackers, :projects_trackers,
           :issue_categories, :enabled_modules, :enumerations, :attachments,
           :workflows, :custom_fields, :custom_values, :custom_fields_projects,
           :custom_fields_trackers, :time_entries, :journals, :journal_details,
           :queries, :news

  def setup
    super
    ApiAuditEvent.delete_all
  end

  # -- what is recorded at each level ---------------------------------------

  def test_a_write_should_be_recorded_at_the_default_level
    with_settings :rest_api_audit_level => 'writes' do
      assert_difference 'ApiAuditEvent.count', 1 do
        post '/issues.json',
             :params => {:issue => {:project_id => 1, :subject => 'audited'}},
             :headers => credentials('jsmith')
      end
      assert_response :created
    end

    event = ApiAuditEvent.last
    assert_equal 'jsmith', event.login
    assert_equal User.find_by_login('jsmith').id, event.user_id
    assert_equal 'POST', event.http_method
    assert_equal 'issues#create', event.endpoint
    assert_equal '/issues.json', event.path
    assert_equal 201, event.status
    assert_equal ApiAuditEvent::CREDENTIAL_HTTP_BASIC, event.credential_type
    assert event.ip.present?
    assert event.created_on.present?
    assert_nil event.impersonator_id
  end

  def test_a_read_should_not_be_recorded_at_the_default_level
    with_settings :rest_api_audit_level => 'writes' do
      assert_no_difference 'ApiAuditEvent.count' do
        get '/issues.json', :headers => credentials('jsmith')
      end
      assert_response :ok
    end
  end

  def test_a_read_should_be_recorded_at_the_all_level
    with_settings :rest_api_audit_level => 'all' do
      assert_difference 'ApiAuditEvent.count', 1 do
        get '/issues.json', :headers => credentials('jsmith')
      end
      assert_response :ok
    end
    assert_equal 'issues#index', ApiAuditEvent.last.endpoint
  end

  def test_nothing_should_be_recorded_when_the_log_is_off
    with_settings :rest_api_audit_level => 'off' do
      assert_no_difference 'ApiAuditEvent.count' do
        post '/issues.json',
             :params => {:issue => {:project_id => 1, :subject => 'not audited'}},
             :headers => credentials('jsmith')
        assert_response :created
        get '/users/current.json', :headers => credentials('bad', 'credentials')
        assert_response :unauthorized
      end
    end
  end

  def test_an_unknown_level_should_fall_back_to_the_default_rather_than_raise
    with_settings :rest_api_audit_level => 'chatty' do
      assert_equal ApiAuditEvent::LEVEL_WRITES, ApiAuditEvent.level
      assert_difference 'ApiAuditEvent.count', 1 do
        post '/issues.json',
             :params => {:issue => {:project_id => 1, :subject => 'audited'}},
             :headers => credentials('jsmith')
      end
    end
  end

  # -- authentication failures ----------------------------------------------

  def test_audit_009_a_rejected_credential_should_be_recorded_at_the_default_level
    with_settings :rest_api_audit_level => 'writes' do
      assert_difference 'ApiAuditEvent.count', 1 do
        get '/users/current.json', :headers => {'X-Redmine-API-Key' => '0' * 40}
      end
      assert_response :unauthorized
    end

    event = ApiAuditEvent.last
    assert_nil event.user_id
    assert_nil event.login
    assert_equal 401, event.status
    assert_equal ApiAuditEvent::CREDENTIAL_API_KEY, event.credential_type
    assert_equal 'users#show', event.endpoint
  end

  def test_audit_009_a_rejected_token_should_be_named_as_a_token_not_as_an_api_key
    with_settings :rest_api_audit_level => 'writes' do
      get '/users/current.json',
          :headers => {'X-Redmine-API-Key' => "#{PersonalAccessToken::PREFIX}#{'0' * 40}"}
      assert_response :unauthorized
    end
    assert_equal ApiAuditEvent::CREDENTIAL_PERSONAL_ACCESS_TOKEN, ApiAuditEvent.last.credential_type
  end

  def test_audit_009_a_rejected_credential_on_an_html_request_should_still_be_recorded
    # accept_api_auth? has no format check, so a credential in a header is read
    # on an HTML request too. api_request? is false here: without the
    # "a credential was offered" signal this failure would go unrecorded.
    with_settings :rest_api_audit_level => 'writes' do
      assert_difference 'ApiAuditEvent.count', 1 do
        get '/users/current', :headers => {'X-Redmine-API-Key' => '0' * 40}
      end
    end
    event = ApiAuditEvent.last
    assert_equal '/users/current', event.path
    assert_equal ApiAuditEvent::CREDENTIAL_API_KEY, event.credential_type
  end

  def test_audit_009_a_refusal_rendered_inside_user_setup_should_be_recorded
    # must_change_password is rendered from within user_setup, which halts the
    # filter chain -- an after_action would never see it.
    user = User.find_by_login('jsmith')
    user.update_column(:must_change_passwd, true)

    with_settings :rest_api_audit_level => 'writes' do
      assert_difference 'ApiAuditEvent.count', 1 do
        get '/issues.json', :headers => credentials('jsmith')
      end
      assert_response :forbidden
    end
    assert_equal 403, ApiAuditEvent.last.status
  end

  def test_audit_009_a_refused_switch_user_header_should_be_recorded
    with_settings :rest_api_audit_level => 'writes' do
      assert_difference 'ApiAuditEvent.count', 1 do
        get '/issues.json',
            :headers => credentials('admin').merge('X-Redmine-Switch-User' => 'nobody')
      end
      assert_response :precondition_failed
    end
    assert_equal 412, ApiAuditEvent.last.status
  end

  # The other two refusals rendered inside user_setup. Only must_change_password
  # was pinned before, and these are the specific cases the ensure-around-
  # process_action hook was chosen for: an after_action never runs for any of
  # the three, so a single one of them passing does not prove the other two.
  def test_audit_009_http_basic_refused_because_2fa_is_active_should_be_recorded
    user = User.generate! do |u|
      u.password = 'my_password'
      u.update(:twofa_scheme => 'totp')
    end

    with_settings :rest_api_audit_level => 'writes' do
      assert_difference 'ApiAuditEvent.count', 1 do
        get '/users/current.json', :headers => credentials(user.login, 'my_password')
      end
      assert_response :unauthorized
    end

    event = ApiAuditEvent.last
    assert_equal 401, event.status
    assert_equal 'users#show', event.endpoint
    # The refusal happens before anything is authenticated, so the row names the
    # attempt rather than an identity.
    assert_nil event.user_id
    assert_equal ApiAuditEvent::CREDENTIAL_HTTP_BASIC, event.credential_type
  end

  def test_audit_009_a_revoked_oauth_token_should_be_recorded
    application = Doorkeeper::Application.create!(
      :name => 'audit test', :redirect_uri => 'urn:ietf:wg:oauth:2.0:oob', :scopes => 'view_issues'
    )
    token = Doorkeeper::AccessToken.create!(
      :application => application, :resource_owner_id => 2, :scopes => 'view_issues'
    )
    token.revoke

    with_settings :rest_api_audit_level => 'writes' do
      assert_difference 'ApiAuditEvent.count', 1 do
        get '/users/current.json',
            :headers => {'HTTP_AUTHORIZATION' => "Bearer #{token.plaintext_token}"}
      end
      assert_response :unauthorized
    end

    event = ApiAuditEvent.last
    assert_equal 401, event.status
    assert_nil event.user_id
    assert_equal ApiAuditEvent::CREDENTIAL_OAUTH, event.credential_type
    # No part of the bearer token reaches the table.
    assert_not_include token.plaintext_token, stored_values(event).compact.join(' ')
  end

  def test_a_disabled_endpoint_refusal_should_be_recorded
    with_settings :rest_api_audit_level => 'writes',
                  :rest_api_disabled_endpoints => ['issues#index'] do
      assert_difference 'ApiAuditEvent.count', 1 do
        get '/issues.json', :headers => credentials('jsmith')
      end
      assert_response :forbidden
    end
    assert_equal 'issues#index', ApiAuditEvent.last.endpoint
  end

  # -- impersonation (AUDIT-R10) --------------------------------------------

  def test_audit_006_impersonation_should_record_both_identities
    admin = User.find_by_login('admin')
    jsmith = User.find_by_login('jsmith')

    with_settings :rest_api_audit_level => 'writes' do
      assert_difference 'ApiAuditEvent.count', 1 do
        post '/issues.json',
             :params => {:issue => {:project_id => 1, :subject => 'as jsmith'}},
             :headers => credentials('admin').merge('X-Redmine-Switch-User' => 'jsmith')
      end
      assert_response :created
    end

    event = ApiAuditEvent.last
    assert_equal jsmith.id, event.user_id
    assert_equal 'jsmith', event.login
    assert_equal admin.id, event.impersonator_id
    assert_equal 'admin', event.impersonator_login
    assert event.impersonated?
  end

  # -- no credential value is ever stored (AUDIT-R7 / AUDIT-002) ------------

  def test_audit_002_an_api_key_in_the_query_string_should_not_reach_the_log
    key = User.find_by_login('jsmith').api_key

    with_settings :rest_api_audit_level => 'all' do
      get "/issues.json?key=#{key}"
      assert_response :ok
    end

    event = ApiAuditEvent.last
    assert_not_nil event
    assert_equal '/issues.json', event.path
    assert_not_includes stored_values(event).join(' '), key
  end

  def test_audit_002_a_personal_access_token_should_be_stored_as_an_id_and_never_as_a_value
    user = User.find_by_login('jsmith')
    token = PersonalAccessToken.create!(:user => user, :name => 'CI', :scope_preset => 'full')
    value = token.value

    with_settings :rest_api_audit_level => 'all' do
      get '/issues.json', :headers => {'X-Redmine-API-Key' => value}
      assert_response :ok
    end

    event = ApiAuditEvent.last
    assert_equal token.id, event.personal_access_token_id
    assert_equal ApiAuditEvent::CREDENTIAL_PERSONAL_ACCESS_TOKEN, event.credential_type
    haystack = stored_values(event).join(' ')
    assert_not_includes haystack, value
    assert_not_includes haystack, token.token_digest
  end

  def test_audit_002_a_password_offered_over_http_basic_should_not_reach_the_log
    password = 'Sup3rSecret!Passw0rd'
    user = User.generate!(:login => 'basicuser', :password => password, :password_confirmation => password)
    User.add_to_project(user, Project.find(1), Role.find(1))

    with_settings :rest_api_audit_level => 'writes' do
      post '/issues.json',
           :params => {:issue => {:project_id => 1, :subject => 'by basic auth'}},
           :headers => credentials('basicuser', password)
      assert_response :created
    end

    event = ApiAuditEvent.last
    assert_equal 'basicuser', event.login
    assert_not_includes stored_values(event).join(' '), password
  end

  def test_the_token_id_should_survive_impersonation
    admin = User.find_by_login('admin')
    token = PersonalAccessToken.create!(:user => admin, :name => 'CI', :scope_preset => 'full')

    with_settings :rest_api_audit_level => 'all' do
      get '/issues.json',
          :headers => {'X-Redmine-API-Key' => token.value, 'X-Redmine-Switch-User' => 'jsmith'}
      assert_response :ok
    end

    event = ApiAuditEvent.last
    assert_equal token.id, event.personal_access_token_id
    assert_equal admin.id, event.impersonator_id
  end

  # -- forged fields (AUDIT-001) -------------------------------------------

  def test_audit_001_control_characters_in_a_logged_field_should_not_survive
    with_settings :rest_api_audit_level => 'writes' do
      get '/users/current.json',
          :headers => {
            'X-Redmine-API-Key' => '0' * 40,
            'HTTP_X_FORWARDED_FOR' => "10.0.0.1\r\n2026-01-01,admin,forged"
          }
      assert_response :unauthorized
    end

    event = ApiAuditEvent.last
    stored_values(event).each do |value|
      assert_no_match(/[[:cntrl:]]/, value.to_s, "#{value.inspect} carries a control character")
    end
  end

  def test_audit_001_an_over_long_field_should_be_clipped_rather_than_stored_whole
    long = 'a' * 400
    assert_equal ApiAuditEvent::TEXT_LIMIT, ApiAuditEvent.clean(long).length
    assert_equal 45, ApiAuditEvent.clean(long, 45).length
  end

  # -- reliability (AUDIT-R8 / AUDIT-007) -----------------------------------

  def test_audit_007_a_logging_failure_should_not_break_the_request
    ApiAuditEvent.stubs(:create!).raises(ActiveRecord::StatementInvalid.new('disk full'))

    with_settings :rest_api_audit_level => 'writes' do
      assert_no_difference 'ApiAuditEvent.count' do
        post '/issues.json',
             :params => {:issue => {:project_id => 1, :subject => 'still created'}},
             :headers => credentials('jsmith')
      end
      assert_response :created
    end
    assert_equal 'still created', Issue.order(:id => :desc).first.subject
  end

  # The stated limit, pinned so the README's claim about it is measured rather
  # than argued: an anonymous caller with no account writes one row per request
  # at the default level, and nothing here throttles it because rate limiting is
  # excluded by the brief. This test exists to make that a documented property
  # rather than a surprise -- if it ever stops being true, the README is wrong.
  def test_an_unauthenticated_caller_writes_a_row_per_request_at_the_default_level
    with_settings :rest_api_audit_level => 'writes' do
      assert_difference 'ApiAuditEvent.count', 3 do
        3.times do
          get '/issues.json', :headers => credentials('nobody', 'garbage')
        end
      end
    end

    event = ApiAuditEvent.last
    assert_nil event.user_id
    assert_nil event.login
    assert_equal ApiAuditEvent::CREDENTIAL_HTTP_BASIC, event.credential_type
  end

  # AUDIT-R17. "Unchanged when the feature is off" is the narrow claim, and it
  # is about a configuration no upgrade ever gets: the default is `writes`. The
  # requirement that matters is that a caller receives byte-for-byte the same
  # response while rows are actually being written -- both for a request the
  # log records and for one it serves.
  def test_the_default_level_should_not_change_what_the_caller_receives
    refused = [ApiAuditEvent::LEVEL_OFF, ApiAuditEvent::LEVEL_WRITES].map do |level|
      with_settings :rest_api_audit_level => level do
        get '/users/current.json', :headers => {'X-Redmine-API-Key' => '0' * 40}
        [response.status, response.headers['Content-Type'], response.body]
      end
    end

    assert_equal refused.first, refused.last
    # Not vacuous: the second pass really did write a row, the first really did
    # not.
    assert_equal 1, ApiAuditEvent.count

    served = [ApiAuditEvent::LEVEL_OFF, ApiAuditEvent::LEVEL_ALL].map do |level|
      with_settings :rest_api_audit_level => level do
        get '/issues/1.json', :headers => credentials('jsmith')
        [response.status, response.headers['Content-Type'], response.body]
      end
    end

    assert_equal served.first, served.last
    assert_equal 200, served.first.first
    assert_equal 2, ApiAuditEvent.count
  end

  # -- coverage boundaries --------------------------------------------------

  def test_a_session_request_for_an_html_page_should_not_be_recorded
    log_user('jsmith', 'jsmith')
    with_settings :rest_api_audit_level => 'all' do
      assert_no_difference 'ApiAuditEvent.count' do
        get '/issues/1'
        assert_response :ok
      end
    end
  end

  # The boundary of the "a credential was offered" signal, stated as a test
  # rather than left for a reader to infer from the README.
  #
  # @api_credential_presented is set inside find_current_user's API branch, so
  # it needs rest_api_enabled? and accept_api_auth? to both hold. my#page
  # declares no accept_api_auth, so Redmine never tries the key at all: the
  # request is answered as anonymous, 302 to the login form, and nothing is
  # recorded. That is a coverage boundary, not a defect -- there was no
  # authentication attempt to fail. Widening it would mean recording a header
  # Redmine ignored, on every HTML page in the product.
  def test_a_credential_offered_to_an_action_that_does_not_accept_api_auth_is_not_recorded
    with_settings :rest_api_audit_level => 'all' do
      assert_no_difference 'ApiAuditEvent.count' do
        get '/my/page', :headers => {'X-Redmine-API-Key' => '0' * 40}
      end
      assert_response :found

      # The control: the same bad key on an action that *does* accept it is
      # recorded, which is what makes the line above a boundary rather than a
      # hole in the mechanism.
      assert_difference 'ApiAuditEvent.count', 1 do
        get '/my/account', :headers => {'X-Redmine-API-Key' => '0' * 40}
      end
    end
  end

  # The complement, and the reason the first clause of audited? carries most of
  # the weight: with the REST API switched off, find_current_user never enters
  # the API branch and so never sets the "credential offered" flag -- but the
  # request is still api_request?, so the refusal is recorded anyway.
  def test_an_api_format_request_is_recorded_even_when_the_rest_api_is_disabled
    with_settings :rest_api_audit_level => 'writes', :rest_api_enabled => '0' do
      assert_difference 'ApiAuditEvent.count', 1 do
        get '/users/current.json', :headers => {'X-Redmine-API-Key' => '0' * 40}
      end
      # 403, not 401: require_login's format.api branch heads :forbidden when
      # rest_api_enabled? is false.
      assert_response :forbidden
    end
    assert_equal 403, ApiAuditEvent.last.status
  end

  def test_audit_010_reading_the_log_should_not_record_itself
    log_user('admin', 'admin')
    with_settings :rest_api_audit_level => 'all' do
      assert_no_difference 'ApiAuditEvent.count' do
        get '/api_audit_events'
        assert_response :ok
        get '/api_audit_events.csv'
        assert_response :ok
      end
    end
  end

  private

  def stored_values(event)
    event.attributes.values
  end
end
