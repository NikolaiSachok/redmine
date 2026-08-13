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

class PersonalAccessTokensControllerTest < Redmine::ControllerTest
  def setup
    User.current = nil
    @request.session[:user_id] = 1
  end

  def test_index_should_list_every_users_tokens
    PersonalAccessToken.create!(:user => User.find(2), :name => 'jsmith token')
    PersonalAccessToken.create!(:user => User.find(3), :name => 'dlopper token')

    get :index

    assert_response :success
    assert_select 'table.list td.name', :text => 'jsmith token'
    assert_select 'table.list td.name', :text => 'dlopper token'
  end

  def test_index_should_show_the_scope_of_each_token
    PersonalAccessToken.create!(:user => User.find(2), :name => 'unscoped')
    PersonalAccessToken.create!(:user => User.find(3), :name => 'read only',
                                :scope_preset => 'read_only')

    get :index

    assert_response :success
    assert_select 'table.list td.scope', :text => 'Full access'
    assert_select 'table.list td.scope', :text => 'Read-only'
  end

  def test_index_should_not_expose_any_token_value
    token = PersonalAccessToken.create!(:user => User.find(2), :name => 'CI')
    value = token.value

    get :index

    assert_response :success
    assert_not_include value, response.body
    assert_not_include token.token_digest, response.body
  end

  def test_index_without_any_token
    get :index

    assert_response :success
    assert_select 'p.nodata'
  end

  def test_index_should_be_denied_to_a_non_admin
    @request.session[:user_id] = 2

    get :index

    assert_response :forbidden
  end

  def test_destroy_should_revoke_another_users_token
    token = PersonalAccessToken.create!(:user => User.find(2), :name => 'CI')

    assert_difference 'PersonalAccessToken.count', -1 do
      delete :destroy, :params => {:id => token.id}
    end
    assert_redirected_to '/personal_access_tokens'
  end

  def test_destroy_should_name_the_owner_in_the_confirmation
    token = PersonalAccessToken.create!(:user => User.find(2), :name => 'CI')

    delete :destroy, :params => {:id => token.id}

    assert_match 'CI', flash[:notice]
    assert_match User.find(2).to_s, flash[:notice]
  end

  # ATTACKS.md PAT-015: flash messages are rendered html_safe, so a token name
  # reaching one is a cross-user stored XSS sink from the owner to the admin.
  def test_pat_015_owner_and_token_name_must_be_escaped_in_the_confirmation
    token = PersonalAccessToken.create!(:user => User.find(2),
                                        :name => '<img src=x onerror=alert(1)>')

    delete :destroy, :params => {:id => token.id}

    assert_not_include '<img', flash[:notice]
    assert_include '&lt;img', flash[:notice]
  end

  def test_destroy_should_be_denied_to_a_non_admin
    token = PersonalAccessToken.create!(:user => User.find(2), :name => 'CI')
    @request.session[:user_id] = 3

    assert_no_difference 'PersonalAccessToken.count' do
      delete :destroy, :params => {:id => token.id}
    end
    assert_response :forbidden
  end

  def test_destroy_should_require_sudo_mode
    token = PersonalAccessToken.create!(:user => User.find(2), :name => 'CI')
    Redmine::SudoMode.stubs(:enabled?).returns(true)

    assert_no_difference 'PersonalAccessToken.count' do
      delete :destroy, :params => {:id => token.id}
    end
    assert_response :success
    assert_select 'input#sudo_password'
  end

  def test_destroy_with_an_unknown_id_should_respond_404
    delete :destroy, :params => {:id => 999999}

    assert_response :not_found
  end

  # UI-002. The administration screen deliberately does *not* follow the
  # self-service screens in being gated on rest_api_enabled?, and this pins the
  # asymmetry so nobody "fixes" it into consistency later.
  #
  # Switching the API off is the first thing anyone does in an incident. Tokens
  # are not destroyed by it -- they are inert while it is off and re-arm the
  # moment it goes back on -- so that is precisely when an administrator needs
  # the screen that revokes them. The menu entry used to be gated, which meant
  # the switch removed the only route to it.
  def test_ui_002_the_admin_screen_should_stay_usable_when_the_rest_api_is_off
    token = PersonalAccessToken.create!(:user => User.find(2), :name => 'live-token')

    with_settings :rest_api_enabled => '0' do
      get :index
      assert_response :success
      assert_select 'table.list td', :text => 'live-token'

      assert_difference 'PersonalAccessToken.count', -1 do
        delete :destroy, :params => {:id => token.id}
      end
      assert_redirected_to '/personal_access_tokens'
    end
  end

  # The navigation half of UI-002: reachable means linked, not merely served.
  def test_ui_002_the_admin_menu_entry_should_survive_the_api_being_switched_off
    with_settings :rest_api_enabled => '0' do
      item = Redmine::MenuManager.items(:admin_menu).detect {|node| node.name == :personal_access_tokens}

      assert_not_nil item, 'the admin menu no longer offers the personal access tokens screen'
      assert item.condition.nil? || item.condition.call(nil),
             'the admin menu entry is hidden while the REST API is off, which is the only route to revocation'
    end
  end
end
