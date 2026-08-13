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

  def parsed_csv(body)
    CSV.parse(body.sub("\xEF\xBB\xBF", '').force_encoding('UTF-8'))
  end

  def assert_no_formula_cell_in(body)
    offenders = parsed_csv(body).flatten.compact.grep(/\A[=+\-@\t\r]/)
    assert_equal [], offenders, "these exported cells would be evaluated as spreadsheet formulas"
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

  # The 7-day window is a *default*, not a floor. An administrator who clears
  # the filter set gets the whole table, and the session then keeps that choice
  # exactly as it keeps any other filter set -- which is the behaviour of every
  # other Query screen in Redmine and is what makes the log usable for an
  # investigation older than a week. The cost is the COUNT(*) the window exists
  # to avoid, and it is the administrator's to spend deliberately.
  def test_an_emptied_filter_set_should_clear_the_default_window_and_be_remembered
    generate_event(:created_on => 30.days.ago, :endpoint => 'issues#old')
    generate_event(:endpoint => 'issues#recent')

    get :index, :params => {:set_filter => 1, :f => ['']}

    assert_response :success
    assert_equal({}, @request.session[:api_audit_query][:filters])
    assert_select 'table.list td', :text => 'issues#old'
    assert_select 'table.list td', :text => 'issues#recent'

    # No set_filter this time: the session query is what answers, and it must
    # still be the emptied one rather than silently snapping back to 7 days.
    # ApiAuditQuery#initialize applies the window with ||=, so an empty hash
    # from the session survives it where a nil would not.
    get :index

    assert_response :success
    assert_select 'table.list td', :text => 'issues#old'
    assert_select 'table.list tbody tr', 2
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

  # The attacker is any user who can create a personal access token; the victim
  # is the administrator who opens the exported log in a spreadsheet. Token
  # names are validated for presence, length and uniqueness and for no format
  # at all, so the bytes are the attacker's choice. The HTML screen is safe
  # because content_tag escapes it; only the CSV was raw.
  def test_audit_005_a_token_name_should_not_inject_a_csv_formula
    token = PersonalAccessToken.create!(:user => User.find(2), :name => "=cmd|'/C calc'!A0")
    generate_event(:credential_type => ApiAuditEvent::CREDENTIAL_PERSONAL_ACCESS_TOKEN,
                   :personal_access_token_id => token.id,
                   :login => '@SUM(1+1)*cmd')

    get :index, :params => {:format => 'csv', :set_filter => 1,
                            :c => ['login', 'personal_access_token']}

    assert_response :success
    assert_include "'=cmd|'/C calc'!A0", response.body
    assert_include "'@SUM(1+1)*cmd", response.body
    assert_no_formula_cell_in response.body
  end

  def test_audit_005_the_export_should_neutralise_every_formula_prefix
    %w(= + - @).each_with_index do |prefix, i|
      generate_event(:login => "#{prefix}HYPERLINK(\"http://evil\")", :endpoint => "issues#a#{i}")
    end

    get :index, :params => {:format => 'csv', :set_filter => 1, :c => ['login', 'endpoint']}

    assert_response :success
    assert_no_formula_cell_in response.body
    assert_equal 5, response.body.split("\n").size
  end

  # A cell that never began a formula must come out byte for byte as it went in:
  # a neutraliser that rewrites ordinary values would make the export unusable
  # as evidence.
  def test_audit_005_an_ordinary_cell_should_not_be_rewritten
    generate_event(:login => 'jsmith')

    get :index, :params => {:format => 'csv', :set_filter => 1, :c => ['login', 'endpoint', 'status']}

    assert_response :success
    row = parsed_csv(response.body).last
    assert_equal ['jsmith', 'issues#create', '201'], row
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

  # UI-004. Saving a query worked and re-running it by URL worked; nothing in
  # the product linked to it, so the only way back was a hand-built query_id.
  # Asserted on the rendered sidebar rather than on the query being saved,
  # because "the row exists" was already true while the defect was present.
  def test_ui_004_a_saved_query_should_be_linked_from_the_sidebar
    query = ApiAuditQuery.create!(:name => 'Refused calls', :user_id => 1, :visibility => Query::VISIBILITY_PRIVATE)

    get :index

    assert_response :success
    assert_select '#sidebar a[href=?]', "/api_audit_events?query_id=#{query.id}", :text => 'Refused calls'
  end

  # The other half of UI-004: the sidebar must not become a disclosure channel.
  # ApiAuditQuery.visible is admin-only in both directions, and this pins that
  # the view honours it rather than listing every saved query it can load.
  def test_ui_004_the_sidebar_should_not_leak_another_users_saved_query
    ApiAuditQuery.create!(:name => 'Admin only', :user_id => 1, :visibility => Query::VISIBILITY_PRIVATE)
    @request.session[:user_id] = 2

    get :index

    assert_response :forbidden
    assert_select 'a', {:text => 'Admin only', :count => 0}
  end

  # UI-007. The heading already showed the query name; the browser title did not.
  def test_ui_007_the_page_title_should_name_the_loaded_query
    query = ApiAuditQuery.create!(:name => 'Refused calls', :user_id => 1, :visibility => Query::VISIBILITY_PRIVATE)

    get :index, :params => {:query_id => query.id}

    assert_response :success
    assert_select 'head title', :text => /Refused calls/
  end

  # The token column is in the *default* set, not merely available. The
  # regression this pins is specific: every existing test that asserts on the
  # token column passes it explicitly with :c, so all of them stayed green while
  # the default screen could not answer "which token".
  def test_the_default_columns_should_name_the_token
    token = PersonalAccessToken.create!(:user => User.find(2), :name => 'CI')
    generate_event(:credential_type => ApiAuditEvent::CREDENTIAL_PERSONAL_ACCESS_TOKEN,
                   :personal_access_token_id => token.id)

    get :index

    assert_response :success
    assert_includes ApiAuditQuery.new.default_columns_names, :personal_access_token
    assert_select 'table.list td.personal_access_token', :text => 'CI'
  end
end
