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

require_relative '../../../test_helper'

class Redmine::ApiEndpointsTest < ActiveSupport::TestCase
  def test_all_should_enumerate_the_accept_api_auth_actions
    all = Redmine::ApiEndpoints.all

    assert_include 'issues#index', all
    assert_include 'issues#create', all
    assert_include 'projects#unarchive', all
    assert_include 'my#account', all
    assert_include 'repositories#add_related_issue', all
  end

  def test_all_should_not_enumerate_an_action_that_does_not_accept_api_auth
    all = Redmine::ApiEndpoints.all

    # declared by IssuesController but absent from its accept_api_auth list
    assert_not_include 'issues#new', all
    assert_not_include 'issues#edit', all
    assert_not_include 'my#page', all
    assert_not_include 'my#api_key', all
  end

  def test_no_administration_screen_should_be_an_endpoint
    # The screen that configures this feature must never be something this
    # feature can switch off. That holds by construction rather than by care:
    # SettingsController does not declare accept_api_auth, so it cannot appear
    # here, and check_api_endpoint_enabled returns early for anything that is
    # not in this list.
    controllers = Redmine::ApiEndpoints.grouped.keys

    assert_not_include 'settings', controllers
    assert_not_include 'admin', controllers
  end

  def test_grouped_should_group_actions_by_controller
    grouped = Redmine::ApiEndpoints.grouped

    assert_equal %w(index show create update destroy), grouped['issues']
    assert_equal %w(account), grouped['my']
    assert_equal grouped.keys.sort, grouped.keys
  end

  def test_grouped_should_agree_with_accept_api_auth
    Redmine::ApiEndpoints.grouped.each do |controller, actions|
      klass = "#{controller.camelize}Controller".constantize
      assert_equal klass.accept_api_auth.map(&:to_s).uniq, actions,
                   "#{controller} does not agree with its accept_api_auth declaration"
    end
  end

  def test_everything_should_be_enabled_by_default
    assert_equal [], Redmine::ApiEndpoints.disabled
    assert Redmine::ApiEndpoints.enabled?('issues', 'index')
    assert_not Redmine::ApiEndpoints.disabled?('issues', 'index')
  end

  def test_disabled_should_read_the_setting
    with_settings :rest_api_disabled_endpoints => ['issues#create'] do
      assert Redmine::ApiEndpoints.disabled?('issues', 'create')
      assert_not Redmine::ApiEndpoints.disabled?('issues', 'index')
      assert_not Redmine::ApiEndpoints.disabled?('news', 'create')
    end
  end

  def test_ep_007_an_endpoint_the_setting_has_never_seen_should_be_enabled
    # A plugin's controller, or one a later Redmine version adds, is not in the
    # stored list and must therefore work. The setting stores what is disabled,
    # never what is enabled, exactly so that this holds.
    with_settings :rest_api_disabled_endpoints => ['issues#index'] do
      assert Redmine::ApiEndpoints.enabled?('some_plugin_things', 'index')
      assert Redmine::ApiEndpoints.enabled?('issues', 'a_future_action')
    end
  end

  def test_a_setting_value_that_is_not_a_list_should_disable_nothing
    # Restricting the API must not be able to take the API down because the
    # stored value got into a shape nothing writes.
    [nil, '', {'issues' => 'index'}, 42, [[]], [nil]].each do |value|
      with_settings :rest_api_disabled_endpoints => value do
        assert_not Redmine::ApiEndpoints.disabled?('issues', 'index'),
                   "#{value.inspect} should not disable issues#index"
      end
    end
  end

  def test_a_single_endpoint_name_should_be_read_as_a_one_name_list
    with_settings :rest_api_disabled_endpoints => 'issues#index' do
      assert Redmine::ApiEndpoints.disabled?('issues', 'index')
      assert_not Redmine::ApiEndpoints.disabled?('issues', 'show')
    end
  end

  def test_ep_006_a_crafted_endpoint_name_should_never_be_stored
    # The stored value is only ever compared as a string, and what the admin
    # form posts is intersected with the endpoints enumerated from the code, so
    # a name that resolves to a class or a method cannot become a setting.
    params = {
      :'issues#index' => '1',
      :'Kernel#system' => '1',
      :'kernel#system' => '1',
      :"issues#index'; DROP TABLE settings; --" => '1',
      :'../../etc/passwd' => '1'
    }

    assert_equal ['issues#index'], Setting.rest_api_disabled_endpoints_from_params(params)
  end

  def test_from_params_should_keep_only_the_endpoints_marked_as_disabled
    params = {:'issues#index' => '1', :'issues#show' => '0', :'news#index' => '1'}

    assert_equal ['issues#index', 'news#index'], Setting.rest_api_disabled_endpoints_from_params(params)
  end

  def test_from_params_should_return_an_empty_list_when_nothing_is_disabled
    assert_equal [], Setting.rest_api_disabled_endpoints_from_params({:'issues#index' => '0'})
    assert_equal [], Setting.rest_api_disabled_endpoints_from_params('issues#index')
    assert_equal [], Setting.rest_api_disabled_endpoints_from_params(nil)
  end

  def test_the_setting_should_round_trip_through_the_database
    Setting.rest_api_disabled_endpoints = ['issues#index', 'my#account']
    Setting.clear_cache

    assert_equal ['issues#index', 'my#account'], Setting.rest_api_disabled_endpoints
    assert Redmine::ApiEndpoints.disabled?('my', 'account')
  ensure
    Setting.rest_api_disabled_endpoints = []
    Setting.clear_cache
  end
end
