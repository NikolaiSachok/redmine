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

class ApiAuditEventsControllerTest < Redmine::ControllerTest
  def setup
    User.current = nil
    ApiAuditEvent.delete_all
    @request.session[:user_id] = 1
  end

  def generate_event(attributes = {})
    ApiAuditEvent.create!({
      :user_id => 2,
      :login => 'jsmith',
      :credential_type => ApiAuditEvent::CREDENTIAL_API_KEY,
      :http_method => 'POST',
      :endpoint => 'issues#create',
      :path => '/issues.json',
      :ip => '10.0.0.1',
      :status => 201,
      :created_on => Time.now
    }.merge(attributes))
  end

  def test_index_should_list_recorded_events
    generate_event
    generate_event(:login => 'dlopper', :user_id => 3, :endpoint => 'issues#update', :http_method => 'PUT')

    get :index

    assert_response :success
    assert_select 'table.list tbody tr', 2
    assert_select 'table.list td', :text => 'issues#create'
    assert_select 'table.list td', :text => 'issues#update'
  end

  def test_audit_004_index_should_be_denied_to_a_non_administrator
    @request.session[:user_id] = 2

    get :index

    assert_response :forbidden
  end

  def test_audit_004_index_should_be_denied_to_anonymous
    @request.session[:user_id] = nil

    get :index

    assert_response :found
    assert_redirected_to '/login?back_url=http%3A%2F%2Ftest.host%2Fapi_audit_events'
  end

  def test_audit_004_csv_export_should_be_denied_to_a_non_administrator
    generate_event
    @request.session[:user_id] = 2

    get :index, :params => {:format => 'csv'}

    assert_response :forbidden
  end

  def test_index_should_default_to_a_time_window
    generate_event(:created_on => 30.days.ago, :endpoint => 'issues#old')
    generate_event(:endpoint => 'issues#recent')

    get :index

    assert_response :success
    assert_select 'table.list td', :text => 'issues#recent'
    assert_select 'table.list td', :text => 'issues#old', :count => 0
  end

  def test_the_default_window_should_be_the_query_default_rather_than_a_view_accident
    assert_equal({'created_on' => {:operator => '>t-', :values => [ApiAuditQuery::DEFAULT_WINDOW_IN_DAYS.to_s]}},
                 ApiAuditQuery.new(:name => '_').filters)
  end

  def test_index_should_filter_by_login
    generate_event
    generate_event(:login => 'dlopper', :user_id => 3)

    get :index, :params => {:set_filter => 1, :f => ['login'], :op => {'login' => '='}, :v => {'login' => ['dlopper']}}

    assert_response :success
    assert_select 'table.list tbody tr', 1
    assert_select 'table.list td', :text => 'dlopper'
  end

  def test_index_should_filter_by_status
    generate_event(:status => 201)
    generate_event(:status => 401, :endpoint => 'users#show')

    get :index, :params => {:set_filter => 1, :f => ['status'], :op => {'status' => '='}, :v => {'status' => ['401']}}

    assert_response :success
    assert_select 'table.list tbody tr', 1
    assert_select 'table.list td', :text => 'users#show'
  end

  def test_index_should_filter_by_credential_type
    generate_event(:credential_type => ApiAuditEvent::CREDENTIAL_API_KEY)
    generate_event(:credential_type => ApiAuditEvent::CREDENTIAL_PERSONAL_ACCESS_TOKEN, :endpoint => 'issues#update')

    get :index,
        :params => {:set_filter => 1, :f => ['credential_type'], :op => {'credential_type' => '='},
                    :v => {'credential_type' => [ApiAuditEvent::CREDENTIAL_PERSONAL_ACCESS_TOKEN]}}

    assert_response :success
    assert_select 'table.list tbody tr', 1
    assert_select 'table.list td', :text => 'issues#update'
  end

  def test_index_should_show_both_identities_of_an_impersonated_call
    generate_event(:impersonator_id => 1, :impersonator_login => 'admin')

    get :index

    assert_response :success
    assert_select 'table.list td', :text => 'jsmith'
    assert_select 'table.list td', :text => 'admin'
  end

  def test_index_should_link_a_login_to_its_account_and_show_a_deleted_one_as_text
    generate_event
    generate_event(:user_id => nil, :login => 'gone', :endpoint => 'issues#update')

    get :index

    assert_response :success
    assert_select 'table.list td a[href=?]', '/users/2', :text => 'jsmith'
    assert_select 'table.list td', :text => 'gone'
  end

  def test_index_should_warn_when_the_log_is_switched_off
    with_settings :rest_api_audit_level => 'off' do
      get :index
      assert_response :success
      assert_select 'p.warning'
    end

    with_settings :rest_api_audit_level => 'writes' do
      get :index
      assert_response :success
      assert_select 'p.warning', :count => 0
    end
  end

  def test_index_csv_should_export_the_events
    generate_event

    get :index, :params => {:format => 'csv'}

    assert_response :success
    assert_include 'text/csv', response.headers['Content-Type']
    assert_include 'issues#create', response.body
    assert_include 'jsmith', response.body
  end

  def test_audit_r11_csv_export_should_respect_the_export_limit
    3.times {|i| generate_event(:endpoint => "issues#a#{i}")}

    with_settings :issues_export_limit => 2 do
      get :index, :params => {:format => 'csv'}
    end

    assert_response :success
    # one header row plus the capped rows
    assert_equal 3, response.body.split("\n").size
  end

  def test_audit_002_the_export_should_carry_no_credential_value
    token = PersonalAccessToken.create!(:user => User.find(2), :name => 'CI')
    generate_event(:credential_type => ApiAuditEvent::CREDENTIAL_PERSONAL_ACCESS_TOKEN,
                   :personal_access_token_id => token.id)

    get :index, :params => {:format => 'csv', :set_filter => 1, :c => ['endpoint', 'personal_access_token']}

    assert_response :success
    assert_not_include token.value, response.body
    assert_not_include token.token_digest, response.body
    # the token is named, so an administrator can act on it, by name and never
    # by anything that could be replayed
    assert_include 'CI', response.body
  end

  def test_index_should_show_a_revoked_token_by_id_rather_than_raise
    generate_event(:credential_type => ApiAuditEvent::CREDENTIAL_PERSONAL_ACCESS_TOKEN,
                   :personal_access_token_id => 999999)

    get :index, :params => {:set_filter => 1, :c => ['personal_access_token']}

    assert_response :success
    assert_select 'table.list td', :text => '#999999'
  end

  def test_audit_008_a_crafted_filter_name_should_be_dropped_rather_than_reach_sql
    generate_event
    crafted = "login) OR 1=1 --"

    get :index,
        :params => {:set_filter => 1, :f => [crafted],
                    :op => {crafted => '='}, :v => {crafted => ['x']}}

    assert_response :success
    # Query#add_filter only accepts names it declared, so the crafted one is
    # never stored and never becomes part of a statement.
    assert_equal 1, ApiAuditEvent.count
    assert_select 'table.list'
  end

  def test_audit_008_a_crafted_filter_value_should_be_bound_rather_than_interpolated
    generate_event(:login => 'jsmith')

    get :index,
        :params => {:set_filter => 1, :f => ['login'], :op => {'login' => '='},
                    :v => {'login' => ["jsmith' OR '1'='1"]}}

    assert_response :success
    assert_equal 1, ApiAuditEvent.count
    assert_select 'table.list tbody tr', 0
  end

  def test_audit_008_a_crafted_sort_parameter_should_not_reach_sql
    generate_event

    get :index, :params => {:sort => 'login); DROP TABLE api_audit_events; --'}

    assert_response :success
    assert_equal 1, ApiAuditEvent.count
  end
end
