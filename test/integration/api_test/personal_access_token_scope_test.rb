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

# Enforcement of token scopes, exercised through the real Rack stack rather
# than against the model, because a scope that is stored and displayed but not
# enforced looks correct in every screenshot.
class Redmine::ApiTest::PersonalAccessTokenScopeTest < Redmine::ApiTest::Base
  def setup
    super
    # jsmith, Manager on project 1, so the writes below are ones the *owner*
    # is allowed to make and only the scope refuses.
    @user = User.find(2)
    @admin = User.find(1)
  end

  def read_only_token(user = @user)
    PersonalAccessToken.create!(:user => user, :name => "read-only-#{user.id}",
                                :scope_preset => PersonalAccessToken::SCOPE_PRESET_READ_ONLY)
  end

  def headers_for(token, extra = {})
    {'X-Redmine-API-Key' => token.value}.merge(extra)
  end

  def test_a_read_only_token_should_be_allowed_to_read
    token = read_only_token

    get '/issues/1.json', :headers => headers_for(token)
    assert_response :ok
    assert_equal 1, ActiveSupport::JSON.decode(response.body)['issue']['id']
  end

  # ATTACKS.md SCOPE-001: the whole feature is worthless if a write path skips
  # the permission check. These are the four verbs against the endpoints the
  # ticket names, all of them writes the owner is otherwise allowed to make.
  def test_scope_001_a_read_only_token_should_be_refused_every_write
    token = read_only_token

    assert_no_difference 'Issue.count' do
      post '/issues.json',
           :params => {:issue => {:project_id => 1, :subject => 'from a read-only token'}},
           :headers => headers_for(token)
      assert_response :forbidden
    end

    put '/issues/1.json',
        :params => {:issue => {:subject => 'rewritten by a read-only token'}},
        :headers => headers_for(token)
    assert_response :forbidden
    assert_not_equal 'rewritten by a read-only token', Issue.find(1).subject

    assert_no_difference 'Issue.count' do
      delete '/issues/1.json', :headers => headers_for(token)
      assert_response :forbidden
    end

    assert_no_difference 'TimeEntry.count' do
      post '/time_entries.json',
           :params => {:time_entry => {:issue_id => 1, :hours => 1, :activity_id => 10}},
           :headers => headers_for(token)
      assert_response :forbidden
    end

    assert_no_difference 'Journal.count' do
      put '/issues/1.json',
          :params => {:issue => {:notes => 'a note from a read-only token'}},
          :headers => headers_for(token)
      assert_response :forbidden
    end
  end

  def test_a_custom_scope_should_allow_exactly_what_it_names
    token = PersonalAccessToken.create!(
      :user => @user, :name => 'issue reader and editor',
      :scope_preset => PersonalAccessToken::SCOPE_PRESET_CUSTOM,
      :permissions => [:view_issues, :edit_issues]
    )

    put '/issues/1.json',
        :params => {:issue => {:subject => 'edited within scope'}},
        :headers => headers_for(token)
    assert_response :no_content
    assert_equal 'edited within scope', Issue.find(1).subject

    # log_time is not in the scope, and the owner does hold it
    assert User.find(2).allowed_to?(:log_time, Project.find(1))
    assert_no_difference 'TimeEntry.count' do
      post '/time_entries.json',
           :params => {:time_entry => {:issue_id => 1, :hours => 1, :activity_id => 10}},
           :headers => headers_for(token)
      assert_response :forbidden
    end
  end

  # ATTACKS.md SCOPE-003: a scope intersects with what the owner may already do,
  # so naming a permission the owner does not hold buys nothing.
  def test_scope_003_a_scope_should_never_grant_a_permission_the_owner_lacks
    Role.find(1).remove_permission!(:edit_issues)
    assert_not User.find(2).allowed_to?(:edit_issues, Project.find(1))

    token = PersonalAccessToken.create!(
      :user => @user, :name => 'wishful thinking',
      :scope_preset => PersonalAccessToken::SCOPE_PRESET_CUSTOM,
      :permissions => [:view_issues, :edit_issues]
    )

    put '/issues/1.json',
        :params => {:issue => {:subject => 'granted by a scope'}},
        :headers => headers_for(token)
    assert_response :forbidden
    assert_not_equal 'granted by a scope', Issue.find(1).subject
  end

  # ATTACKS.md SCOPE-005: an admin bypass makes every other restriction
  # cosmetic, so admin? has to consult the scope the way it does for oauth.
  def test_scope_005_a_scoped_token_of_an_administrator_should_not_be_an_administrator
    token = read_only_token(@admin)

    get '/users.json', :headers => headers_for(token)
    assert_response :forbidden

    assert_no_difference 'User.count' do
      post '/users.json',
           :params => {:user => {:login => 'scoped', :firstname => 'S', :lastname => 'C',
                                 :mail => 'scoped@example.net', :password => 'Secret1234!'}},
           :headers => headers_for(token)
      assert_response :forbidden
    end
  end

  def test_a_token_scoped_with_admin_should_still_administer
    token = PersonalAccessToken.create!(
      :user => @admin, :name => 'admin scope',
      :scope_preset => PersonalAccessToken::SCOPE_PRESET_CUSTOM,
      :permissions => [:admin]
    )

    get '/users.json', :headers => headers_for(token)
    assert_response :ok
  end

  # ATTACKS.md SCOPE-002: exactly the shape of PAT-002. Impersonation replaces
  # the user object, and a per-request property recorded on that object was
  # silently dropped the last time this happened.
  def test_scope_002_the_scope_should_survive_a_switch_user_header
    token = PersonalAccessToken.create!(
      :user => @admin, :name => 'narrow admin',
      :scope_preset => PersonalAccessToken::SCOPE_PRESET_CUSTOM,
      :permissions => [:admin, :view_issues]
    )
    switch = {'X-Redmine-Switch-User' => @user.login}

    get '/users/current.json', :headers => headers_for(token, switch)
    assert_response :ok
    assert_equal @user.id, ActiveSupport::JSON.decode(response.body)['user']['id']

    get '/issues/1.json', :headers => headers_for(token, switch)
    assert_response :ok

    # jsmith may edit this issue; the scope carried over from the admin's token
    # is what refuses it
    assert User.find(2).allowed_to?(:edit_issues, Project.find(1))
    put '/issues/1.json',
        :params => {:issue => {:subject => 'written after switching user'}},
        :headers => headers_for(token, switch)
    assert_response :forbidden
    assert_not_equal 'written after switching user', Issue.find(1).subject
  end

  def test_scope_002_a_scoped_token_without_the_admin_scope_should_not_switch_user
    token = read_only_token(@admin)

    get '/users/current.json',
        :headers => headers_for(token, 'X-Redmine-Switch-User' => @user.login)
    # not an administrator for this request, so the header is simply ignored,
    # as it is for any non-admin credential
    assert_response :ok
    assert_equal @admin.id, ActiveSupport::JSON.decode(response.body)['user']['id']
  end

  # ATTACKS.md SCOPE-001: editing your own account is not expressible as a
  # permission, so no scope can name it. Refused rather than allowed by default,
  # because the mail address is a password-reset pivot.
  def test_scope_001_a_scoped_token_should_not_update_its_owners_account
    token = read_only_token

    put '/my/account.json',
        :params => {:user => {:firstname => 'Rewritten'}},
        :headers => headers_for(token)
    assert_response :forbidden
    assert_not_equal 'Rewritten', User.find(2).firstname

    get '/my/account.json', :headers => headers_for(token)
    assert_response :ok
  end

  def test_an_unscoped_token_should_still_update_its_owners_account
    token = PersonalAccessToken.create!(:user => @user, :name => 'unscoped')

    put '/my/account.json',
        :params => {:user => {:firstname => 'Rewritten'}},
        :headers => headers_for(token)
    assert_response :no_content
    assert_equal 'Rewritten', User.find(2).firstname
  end

  # SCOPE-R10: a token issued before scopes existed has a NULL scope, which
  # means unrestricted, not empty.
  def test_a_token_with_no_scope_should_keep_full_access
    token = PersonalAccessToken.create!(:user => @user, :name => 'legacy')
    assert_nil token.reload.permissions

    put '/issues/1.json',
        :params => {:issue => {:subject => 'edited by an unscoped token'}},
        :headers => headers_for(token)
    assert_response :no_content
    assert_equal 'edited by an unscoped token', Issue.find(1).subject
  end

  # SCOPE-R12: the legacy credential is untouched by any of this.
  def test_the_legacy_api_key_should_remain_unscoped
    key = @admin.api_key

    get '/users.json', :headers => {'X-Redmine-API-Key' => key}
    assert_response :ok

    put '/issues/1.json',
        :params => {:issue => {:subject => 'edited by an api key'}},
        :headers => {'X-Redmine-API-Key' => key}
    assert_response :no_content
  end

  # SCOPE-R13 / ATTACKS.md SCOPE-010, pinned as a *limit* rather than a defence,
  # and measured rather than asserted from reading.
  #
  # Project.allowed_to_condition calls role.allowed_to?(permission) with no
  # scope (app/models/project.rb:211 and :225), so every `visible` scope built
  # on it ignores the token scope. Redmine's own oauth scoping is porous in the
  # same place. What it costs in practice: a controller action that is gated by
  # `authorize` is scoped, and a listing action that is gated by visibility
  # alone is not. ProjectsController#index is the second kind, so a token whose
  # scope does not name :view_project still lists projects, while GET on one
  # project is refused. Fixing it means changing oauth behaviour, which is a
  # different change from this one.
  def test_scope_010_a_listing_gated_only_by_visibility_ignores_the_scope
    token = PersonalAccessToken.create!(
      :user => @user, :name => 'no view_project',
      :scope_preset => PersonalAccessToken::SCOPE_PRESET_CUSTOM,
      :permissions => [:view_issues]
    )
    assert_not_includes token.permissions, :view_project

    get '/projects.json', :headers => headers_for(token)
    assert_response :ok
    assert ActiveSupport::JSON.decode(response.body)['projects'].any?

    # the per-record read, which does go through authorize, is refused
    get '/projects/1.json', :headers => headers_for(token)
    assert_response :forbidden
  end
end
