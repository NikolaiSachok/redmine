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

class MyControllerTest < Redmine::ControllerTest
  def setup
    @request.session[:user_id] = 2
    # rest_api_enabled defaults to 0, and the personal access token screens are
    # gated on it (UI-001) exactly as the API key block beside them already was.
    # The token tests below therefore have to declare the setting they depend
    # on; the two that assert the gate itself override this with with_settings.
    Setting.rest_api_enabled = '1'
  end

  def test_index
    get :index
    assert_response :success
    assert_select 'h2', 'My page'
  end

  def test_page
    get :page
    assert_response :success
    assert_select 'h2', 'My page'
  end

  def test_page_with_timelog_block
    preferences = User.find(2).pref
    preferences[:my_page_layout] = {'top' => ['timelog']}
    preferences.save!
    with_issue =
      TimeEntry.create!(
        :user => User.find(2), :spent_on => Date.yesterday,
        :hours => 2.5, :activity_id => 10, :issue_id => 1
      )
    without_issue =
      TimeEntry.create!(
        :user => User.find(2), :spent_on => Date.yesterday,
        :hours => 3.5, :activity_id => 10, :project_id => 1
      )
    get :page
    assert_response :success
    assert_select "tr#time-entry-#{with_issue.id}" do
      assert_select 'td.subject a[href="/issues/1"]'
      assert_select 'td.hours', :text => '2:30'
    end
    assert_select "tr#time-entry-#{without_issue.id}" do
      assert_select 'td.hours', :text => '3:30'
    end
  end

  def test_page_with_assigned_issues_block_and_no_custom_settings
    preferences = User.find(2).pref
    preferences.my_page_layout = {'top' => ['issuesassignedtome']}
    preferences.my_page_settings = nil
    preferences.save!

    get :page
    assert_select '#block-issuesassignedtome' do
      assert_select 'table.issues' do
        assert_select 'th a[data-remote=true][data-method=post]', :text => 'Tracker'
      end
      assert_select '#issuesassignedtome-settings' do
        assert_select 'select[name=?]', 'settings[issuesassignedtome][columns][]'
      end
    end
  end

  def test_page_with_assigned_issues_block_and_custom_columns
    preferences = User.find(2).pref
    preferences.my_page_layout = {'top' => ['issuesassignedtome']}
    preferences.my_page_settings =
      {'issuesassignedtome' => {:columns => ['tracker', 'subject', 'due_date']}}
    preferences.save!

    get :page
    assert_select '#block-issuesassignedtome' do
      assert_select 'table.issues td.due_date'
    end
  end

  def test_page_with_assigned_issues_block_and_custom_sort
    preferences = User.find(2).pref
    preferences.my_page_layout = {'top' => ['issuesassignedtome']}
    preferences.my_page_settings = {'issuesassignedtome' => {:sort => 'due_date'}}
    preferences.save!

    get :page
    assert_select '#block-issuesassignedtome' do
      assert_select 'table.issues.sort-by-due-date'
    end
  end

  def test_page_with_issuequery_block_and_no_settings
    user = User.find(2)
    user.pref.my_page_layout = {'top' => ['issuequery']}
    user.pref.save!

    get :page
    assert_response :success

    assert_select '#block-issuequery' do
      assert_select 'h3', :text => 'Issues'
      assert_select 'select[name=?]', 'settings[issuequery][query_id]' do
        assert_select 'option[value="5"]', :text => 'Open issues by priority and tracker'
      end
    end
  end

  def test_page_with_issuequery_block_and_global_query
    user = User.find(2)
    query =
      IssueQuery.create!(
        :name => 'All issues', :user => user,
        :column_names => [:tracker, :subject, :status, :assigned_to]
      )
    user.pref.my_page_layout = {'top' => ['issuequery']}
    user.pref.my_page_settings = {'issuequery' => {:query_id => query.id}}
    user.pref.save!

    get :page
    assert_response :success

    assert_select '#block-issuequery' do
      assert_select 'a[href=?]', "/issues?query_id=#{query.id}"
      # assert number of columns (columns from query + id column + checkbox column)
      assert_select 'table.issues th', 7
      # assert results limit
      assert_select 'table.issues tr.issue', 10
      assert_select 'table.issues td.assigned_to'
    end
  end

  def test_page_with_issuequery_block_and_project_query
    user = User.find(2)
    query =
      IssueQuery.create!(
        :name => 'All issues', :project => Project.find(1),
        :user => user,
        :column_names => [:tracker, :subject, :status, :assigned_to]
      )
    user.pref.my_page_layout = {'top' => ['issuequery']}
    user.pref.my_page_settings = {'issuequery' => {:query_id => query.id}}
    user.pref.save!

    get :page
    assert_response :success

    assert_select '#block-issuequery' do
      assert_select 'a[href=?]', "/projects/ecookbook/issues?query_id=#{query.id}"
      # assert number of columns (columns from query + id column + checkbox column)
      assert_select 'table.issues th', 7
      # assert results limit
      assert_select 'table.issues tr.issue', 10
      assert_select 'table.issues td.assigned_to'
    end
  end

  def test_page_with_issuequery_block_and_query_should_display_custom_columns
    user = User.find(2)
    query =
      IssueQuery.create!(
        :name => 'All issues', :user => user,
        :column_names => [:tracker, :subject, :status, :assigned_to]
      )
    user.pref.my_page_layout = {'top' => ['issuequery']}
    user.pref.my_page_settings = {
      'issuequery' => {:query_id => query.id, :columns => [:subject, :due_date]}
    }
    user.pref.save!

    get :page
    assert_response :success

    assert_select '#block-issuequery' do
      # assert number of columns (columns from query + id column + checkbox column)
      assert_select 'table.issues th', 5
      assert_select 'table.issues th', :text => 'Due date'
    end
  end

  def test_page_with_multiple_issuequery_blocks
    user = User.find(2)
    query1 =
      IssueQuery.create!(:name => 'All issues', :user => user,
                         :column_names => [:tracker, :subject, :status, :assigned_to])
    query2 =
      IssueQuery.create!(:name => 'Other issues', :user => user,
                         :column_names => [:tracker, :subject, :priority])
    user.pref.my_page_layout = {'top' => ['issuequery__1', 'issuequery']}
    user.pref.my_page_settings = {
      'issuequery' => {:query_id => query1.id, :columns => [:subject, :due_date]},
      'issuequery__1' => {:query_id => query2.id}
    }
    user.pref.save!

    get :page
    assert_response :success

    assert_select '#block-issuequery' do
      assert_select 'h3', :text => /All issues/
      assert_select 'table.issues th', :text => 'Due date'
    end

    assert_select '#block-issuequery__1' do
      assert_select 'h3', :text => /Other issues/
      assert_select 'table.issues th', :text => 'Priority'
    end

    assert_select '#block-select' do
      assert_select 'option[value=?]:not([disabled])', 'issuequery__2', :text => 'Issues'
    end
  end

  def test_page_with_activity
    user = User.find(2)
    user.pref.my_page_layout = {'top' => ['activity']}
    user.pref.time_zone = 'UTC'
    user.pref.save!

    get :page
    assert_response :success

    assert_select 'div#block-activity' do
      assert_select 'h3' do
        assert_select(
          'a[href=?]', activity_path(from: User.current.today, user_id: user.id),
          :text => 'Activity'
        )
      end
      assert_select 'div#activity' do
        assert_select 'dt', 10
      end
    end
  end

  def test_page_with_updated_issues_block
    preferences = User.find(2).pref
    preferences.my_page_layout = {'top' => ['issuesupdatedbyme']}
    preferences.my_page_settings = {'issuesupdatedbyme' => {}}
    preferences.save!

    project = Project.find(3)
    project.close

    get :page

    assert_response :success
    assert_select '#block-issuesupdatedbyme' do
      report_url = CGI.unescape(css_select('h3 a').first.attr(:href))
      assert_match 'f[]=project.status', report_url
      assert_match 'v[project.status][]=1', report_url
      assert_match 'f[]=updated_by', report_url
      assert_match 'v[updated_by][]=me', report_url

      assert_select 'table.issues tbody tr', 2
      assert_select 'table.issues tbody tr[id=?]', 'issue-1' do
        assert_select 'td.subject a', :text => 'Cannot print recipes', :count => 1
      end
      assert_select 'table.issues tbody tr[id=?]', 'issue-14', 0
    end
  end

  def test_page_with_all_blocks
    blocks = Redmine::MyPage.blocks.keys
    preferences = User.find(2).pref
    preferences[:my_page_layout] = {'top' => blocks}
    preferences.save!

    get :page
    assert_response :success
    assert_select 'div.mypage-box', blocks.size
  end

  def test_page_with_assigned_issues_block_should_not_show_issues_from_closed_projects
    preferences = User.find(2).pref
    preferences.my_page_layout = {'top' => ['issuesassignedtome']}
    preferences.my_page_settings = {'issuesassignedtome' => {}}
    preferences.save!

    issue = Issue.find(1)
    issue.assigned_to = User.find(2)
    issue.save!

    project = Project.find(2)
    project.close
    project.save

    get :page

    assert_response :success
    assert_select '#block-issuesassignedtome table.issues tbody' do
      report_url = css_select('h3 a').map {|e| e.attr(:href)}.first
      assert_match 'f%5B%5D=project.status', report_url
      assert_match 'v%5Bproject.status%5D%5B%5D=1', report_url

      assert_select 'tr', 1
      assert_select 'tr[id=?]', 'issue-1' do
        assert_select 'td.subject a', :text => 'Cannot print recipes', :count => 1
      end
      assert_select 'tr[id=?]', 'issue-4', 0
    end
  end

  def test_page_with_reported_issues_block_should_not_show_issues_from_closed_projects
    preferences = User.find(2).pref
    preferences.my_page_layout = {'top' => ['issuesreportedbyme']}
    preferences.my_page_settings = {'issuesreportedbyme' => {}}
    preferences.save!

    issue = Issue.find(1)
    issue.assigned_to = User.find(2)
    issue.save!

    project = Project.find(2)
    project.close
    project.save

    get :page

    assert_response :success
    assert_select '#block-issuesreportedbyme' do
      report_url = css_select('h3 a').map {|e| e.attr(:href)}.first
      assert_match 'f%5B%5D=project.status', report_url
      assert_match 'v%5Bproject.status%5D%5B%5D=1', report_url

      assert_select 'table.issues tbody tr', 10
      assert_select 'table.issues tbody tr[id=?]', 'issue-1' do
        assert_select 'td.subject a', :text => 'Cannot print recipes', :count => 1
      end
      assert_select 'table.issues tbody tr[id=?]', 'issue-4', 0
    end
  end

  def test_page_with_watched_issues_block_should_not_show_issues_from_closed_projects
    preferences = User.find(2).pref
    preferences.my_page_layout = {'top' => ['issueswatched']}
    preferences.my_page_settings = {'issueswatched' => {}}
    preferences.save!

    issue = Issue.find(1)
    issue.watcher_user_ids = ['1', '2']
    issue.save!

    issue2 = Issue.find(4)
    issue2.watcher_user_ids = ['2']
    issue2.save!

    project = Project.find(2)
    project.close
    project.save

    get :page

    assert_response :success
    assert_select '#block-issueswatched table.issues tbody' do
      report_url = css_select('h3 a').map {|e| e.attr(:href)}.first
      assert_match 'f%5B%5D=project.status', report_url
      assert_match 'v%5Bproject.status%5D%5B%5D=1', report_url

      assert_select 'tr', 1
      assert_select 'tr[id=?]', 'issue-1' do
        assert_select 'td.subject a', :text => 'Cannot print recipes', :count => 1
      end
      assert_select 'tr[id=?]', 'issue-4', 0
    end
  end

  def test_my_account_should_show_editable_custom_fields
    get :account
    assert_response :success
    assert_select 'input[name=?]', 'user[custom_field_values][4]'
  end

  def test_my_account_should_not_show_non_editable_custom_fields
    UserCustomField.find(4).update_attribute :editable, false

    get :account
    assert_response :success
    assert_select 'input[name=?]', 'user[custom_field_values][4]', 0
  end

  def test_my_account_should_show_language_select
    get :account
    assert_response :success
    assert_select 'select[name=?]', 'user[language]'
  end

  def test_my_account_with_avatar_enabled_should_link_to_edit_avatar
    with_settings :gravatar_enabled => '1' do
      Redmine::Configuration.with 'avatar_server_url' => 'https://gravatar.com' do
        get :account
        assert_response :success
        assert_select 'a[href=?] img.gravatar', 'https://gravatar.com'
      end
    end
  end

  def test_my_account_should_not_show_language_select_with_force_default_language_for_loggedin
    with_settings :force_default_language_for_loggedin => '1' do
      get :account
      assert_response :success
      assert_select 'select[name=?]', 'user[language]', 0
    end
  end

  def test_page_with_calendar
    date = '2020-10-21'
    subject = 'calendar on my page'
    issue = Issue.generate!(:start_date => date,
                            :due_date   => date,
                            :project_id => 1,
                            :tracker_id => 1,
                            :subject => subject)

    travel_to date

    preferences = User.find(2).pref
    preferences[:my_page_layout] = {'top' => ['calendar']}
    preferences.save!

    with_settings :start_of_week => 7 do
      get :page
    end
    assert_response :success

    assert_select 'form[data-cm-url=?]', '/issues/context_menu'

    assert_select 'ul.cal' do
      assert_select 'li' do
        assert_select(
          'div.issue.hascontextmenu.tooltip.starting.ending',
          :text => /eCookbook.*#{subject}/m
        ) do
          assert_select(
            'a.issue[href=?]', "/issues/#{issue.id}",
            :text => "Bug ##{issue.id}"
          )
          assert_select(
            'input[name=?][type=?][value=?]',
            'ids[]',
            'checkbox',
            issue.id.to_s
          )
        end
      end
    end
  end

  def test_update_account
    put(
      :account,
      :params => {
        :user => {
          :firstname => "Joe",
          :login => "root",
          :admin => 1,
          :group_ids => ['10'],
          :custom_field_values => {
            "4" => "0100562500"
          }
        }
      }
    )
    assert_redirected_to '/my/account'
    user = User.find(2)
    assert_equal "Joe", user.firstname
    assert_equal "jsmith", user.login
    assert_equal "0100562500", user.custom_value_for(4).value
    # ignored
    assert !user.admin?
    assert user.groups.empty?
  end

  def test_update_account_should_send_security_notification
    ActionMailer::Base.deliveries.clear
    put(
      :account,
      :params => {
        :user => {
          :mail => 'foobar@example.com'

        }
      }
    )
    assert_not_nil (mail = ActionMailer::Base.deliveries.last)
    assert_mail_body_match '0.0.0.0', mail
    assert_mail_body_match(
      I18n.t(:mail_body_security_notification_change_to,
             :field => I18n.t(:field_mail), :value => 'foobar@example.com'),
      mail
    )
    assert_select_email do
      assert_select 'a[href^=?]', 'http://localhost:3000/my/account', :text => 'My account'
    end
    # The old email address should be notified about the change for security purposes
    assert mail.to.include?(User.find(2).mail)
    assert mail.to.include?('foobar@example.com')
  end

  def test_my_account_notify_about_high_priority_issues_preference
    # normally, preference should be shown
    get :account
    assert_select 'label[for="pref_notify_about_high_priority_issues"]'

    # preference should be persisted
    put(
      :account,
      :params => {
        :pref => {
          notify_about_high_priority_issues: '1'
        }
      }
    )
    assert User.find(2).notify_about_high_priority_issues?

    # preference should be hidden if there aren't any priorities
    Issue.destroy_all
    IssuePriority.destroy_all
    get :account
    assert_select 'label[for="pref_notify_about_high_priority_issues"]', false

    # preference should be hidden if there isn't a "high" priority
    a = IssuePriority.create! name: 'A'
    get :account
    assert_select 'label[for="pref_notify_about_high_priority_issues"]', false

    # preference should be shown if there are at least two priorities (one low, one high)
    b = IssuePriority.create! name: 'B'
    get :account
    assert_select 'label[for="pref_notify_about_high_priority_issues"]'

    # preference should be hidden if the highest priority is the default one,
    # because that means that there is no "high" priority
    b.update! is_default: true
    get :account
    assert_select 'label[for="pref_notify_about_high_priority_issues"]', false
  end

  def test_my_account_should_show_destroy_link
    get :account
    assert_select 'a[href="/my/account/destroy"]'
  end

  def test_get_destroy_should_display_the_destroy_confirmation
    get :destroy
    assert_response :success
    assert_select 'form[action="/my/account/destroy"]' do
      assert_select 'input[name=confirm]'
    end
  end

  def test_post_destroy_without_confirmation_should_not_destroy_account
    assert_no_difference 'User.count' do
      post :destroy
    end
    assert_response :success
  end

  def test_post_destroy_without_confirmation_should_destroy_account
    assert_difference 'User.count', -1 do
      post(
        :destroy,
        :params => {
          :confirm => '1'
        }
      )
    end
    assert_redirected_to '/'
    assert_match /deleted/i, flash[:notice]
  end

  def test_post_destroy_with_unsubscribe_not_allowed_should_not_destroy_account
    User.any_instance.stubs(:own_account_deletable?).returns(false)

    assert_no_difference 'User.count' do
      post(
        :destroy,
        :params => {
          :confirm => '1'
        }
      )
    end
    assert_redirected_to '/my/account'
  end

  def test_change_password
    get :password
    assert_response :success
    assert_includes @response.headers['Cache-Control'], 'no-store'
    assert_select 'input[type=password][name=password][autocomplete=current-password]'
    assert_select 'input[type=password][name=new_password][autocomplete=new-password]'
    assert_select 'input[type=password][name=new_password_confirmation][autocomplete=new-password]'
  end

  def test_update_password
    post(
      :password,
      :params => {
        :password => 'jsmith',
        :new_password => 'secret123',
        :new_password_confirmation => 'secret123'
      }
    )
    assert_redirected_to '/my/account'
    assert User.try_to_login('jsmith', 'secret123')
  end

  def test_update_password_with_non_matching_confirmation
    post(
      :password,
      :params => {
        :password => 'jsmith',
        :new_password => 'secret123',
        :new_password_confirmation => 'secret1234'
      }
    )
    assert_response :success
    assert_select_error /Password doesn.*t match confirmation/
    assert User.try_to_login('jsmith', 'jsmith')
  end

  def test_update_password_with_wrong_password
    # wrong password
    post(
      :password,
      :params => {
        :password => 'wrongpassword',
        :new_password => 'secret123',
        :new_password_confirmation => 'secret123'
      }
    )
    assert_response :success
    assert_equal 'Wrong password', flash[:error]
    assert User.try_to_login('jsmith', 'jsmith')
  end

  def test_change_password_should_redirect_if_user_cannot_change_its_password
    User.find(2).update_attribute(:auth_source_id, 1)

    get :password
    assert_not_nil flash[:error]
    assert_redirected_to '/my/account'
  end

  def test_update_password_should_send_security_notification
    ActionMailer::Base.deliveries.clear
    post(
      :password,
      :params => {
        :password => 'jsmith',
        :new_password => 'secret123',
        :new_password_confirmation => 'secret123'
      }
    )
    assert_not_nil (mail = ActionMailer::Base.deliveries.last)
    assert_mail_body_no_match 'secret123', mail # just to be sure: pw should never be sent!
    assert_select_email do
      assert_select 'a[href^=?]', 'http://localhost:3000/my/password', :text => 'Change password'
    end
  end

  def test_update_page_with_blank_preferences
    user = User.generate!(:language => 'en')
    @request.session[:user_id] = user.id

    post(
      :update_page,
      :params => {
        :settings => {
          'issuesassignedtome' => {
            'columns' => ['subject', 'due_date']
          }
        }
      },
      :xhr => true
    )
    assert_response :success
    assert_include '$("#block-issuesassignedtome").replaceWith(', response.body
    assert_include 'Due date', response.body

    assert_equal({:columns => ['subject', 'due_date']},
                 user.reload.pref.my_page_settings('issuesassignedtome'))
  end

  def test_add_block
    post(
      :add_block,
      :params => {
        :block => 'issueswatched'
      }
    )
    assert_redirected_to '/my/page'
    assert User.find(2).pref[:my_page_layout]['top'].include?('issueswatched')
  end

  def test_add_block_xhr
    post(
      :add_block,
      :params => {
        :block => 'issueswatched'
      },
      :xhr => true
    )
    assert_response :success
    assert_include 'issueswatched', User.find(2).pref[:my_page_layout]['top']
  end

  def test_add_invalid_block_should_error
    post(
      :add_block,
      :params => {
        :block => 'invalid'
      }
    )
    assert_response :unprocessable_content
  end

  def test_remove_block
    post(
      :remove_block,
      :params => {
        :block => 'issuesassignedtome'
      }
    )
    assert_redirected_to '/my/page'
    assert !User.find(2).pref[:my_page_layout].values.flatten.include?('issuesassignedtome')
  end

  def test_remove_block_xhr
    post(
      :remove_block,
      :params => {
        :block => 'issuesassignedtome'
      },
      :xhr => true
    )
    assert_response :success
    assert_include '$("#block-issuesassignedtome").remove();', response.body
    assert !User.find(2).pref[:my_page_layout].values.flatten.include?('issuesassignedtome')
  end

  def test_order_blocks
    pref = User.find(2).pref
    pref.my_page_layout = {'left' => ['news', 'calendar', 'documents']}
    pref.save!

    post(
      :order_blocks,
      :params => {
        :group => 'left',
        :blocks => ['documents', 'calendar', 'news']
      },
      :xhr => true
    )
    assert_response :success
    assert_equal ['documents', 'calendar', 'news'], User.find(2).pref.my_page_layout['left']
  end

  def test_move_block
    pref = User.find(2).pref
    pref.my_page_layout = {'left' => ['news', 'documents'], 'right' => ['calendar']}
    pref.save!

    post(
      :order_blocks,
      :params => {
        :group => 'left',
        :blocks => ['news', 'calendar', 'documents']
      },
      :xhr => true
    )
    assert_response :success
    assert_equal({'left' => ['news', 'calendar', 'documents'],
                 'right' => []},
                 User.find(2).pref.my_page_layout)
  end

  def test_reset_atom_key_with_existing_key
    @previous_token_value = User.find(2).atom_key # Will generate one if it's missing
    post :reset_atom_key

    assert_not_equal @previous_token_value, User.find(2).atom_key
    assert User.find(2).atom_token
    assert_match /reset/, flash[:notice]
    assert_redirected_to '/my/account'
  end

  def test_reset_atom_key_without_existing_key
    Token.delete_all
    assert_nil User.find(2).atom_token
    post :reset_atom_key

    assert User.find(2).atom_token
    assert_match /reset/, flash[:notice]
    assert_redirected_to '/my/account'
  end

  def test_show_api_key
    get :show_api_key
    assert_response :success
    assert_select 'pre', User.find(2).api_key
  end

  def test_reset_api_key_with_existing_key
    @previous_token_value = User.find(2).api_key # Will generate one if it's missing
    post :reset_api_key

    assert_not_equal @previous_token_value, User.find(2).api_key
    assert User.find(2).api_token
    assert_match /reset/, flash[:notice]
    assert_redirected_to '/my/account'
  end

  def test_reset_api_key_without_existing_key
    assert_nil User.find(2).api_token
    post :reset_api_key

    assert User.find(2).api_token
    assert_match /reset/, flash[:notice]
    assert_redirected_to '/my/account'
  end

  def test_personal_access_tokens_without_any_token
    get :personal_access_tokens

    assert_response :success
    assert_select 'p.nodata'
    # the list page offers creation but does not itself create
    assert_select 'div.contextual a.icon-add[href=?]', '/my/personal_access_tokens/new'
    assert_select 'input#personal_access_token_name', 0
  end

  def test_account_sidebar_should_link_to_personal_access_tokens
    with_settings :rest_api_enabled => '1' do
      get :account

      assert_response :success
      assert_select '#sidebar a[href=?]', '/my/personal_access_tokens'
      # the API key block the new link sits beside is asserted by a system test
      # that cannot run in this container; pin its markup here too
      assert_select '#sidebar #api-access-key'
      assert_select '#sidebar .api-key-actions .copy-api-key-link'
    end
  end

  # UI-001. The sidebar link was already hidden when the API is off; the screens
  # behind it were not, so a user could still reach them by URL and mint a token
  # that cannot authenticate anything -- find_current_user never enters the API
  # branch while the setting is off. Hiding a link is not authorization, so all
  # four actions are asserted, not just the one the link pointed at.
  def test_ui_001_the_token_screens_should_be_refused_when_the_rest_api_is_off
    token = PersonalAccessToken.create!(:user => User.find(2), :name => 'existing')

    with_settings :rest_api_enabled => '0' do
      get :personal_access_tokens
      assert_response :forbidden

      get :new_personal_access_token
      assert_response :forbidden

      assert_no_difference 'PersonalAccessToken.count' do
        post :create_personal_access_token,
             :params => {:personal_access_token => {:name => 'api-off-token'}}
      end
      assert_response :forbidden

      assert_no_difference 'PersonalAccessToken.count' do
        delete :revoke_personal_access_token, :params => {:id => token.id}
      end
      assert_response :forbidden
    end
  end

  # The complement, so the gate cannot be satisfied by refusing everything.
  def test_ui_001_the_token_screens_should_work_when_the_rest_api_is_on
    with_settings :rest_api_enabled => '1' do
      get :personal_access_tokens
      assert_response :success

      get :new_personal_access_token
      assert_response :success

      assert_difference 'PersonalAccessToken.count', 1 do
        post :create_personal_access_token,
             :params => {:personal_access_token => {:name => 'api-on-token'}}
      end
      assert_response :success
    end
  end

  # UI-003. The error named a control that was not on screen: the permission
  # checkboxes are in a collapsed fieldset, and nothing expanded it when the
  # record came back rejected for having none. Every user choosing a custom
  # scope met this on their first attempt.
  def test_ui_003_a_rejected_custom_scope_should_show_the_permissions_it_is_asking_for
    assert_no_difference 'PersonalAccessToken.count' do
      post :create_personal_access_token,
           :params => {:personal_access_token => {:name => 'custom', :scope_preset => 'custom'}}
    end

    assert_response :success
    assert_select '#errorExplanation'
    assert_select 'fieldset#personal-access-token-permissions' do
      assert_select 'legend.icon-expanded'
    end
    assert_select 'fieldset#personal-access-token-permissions.collapsed', 0
    assert_select 'fieldset#personal-access-token-permissions div.hidden', 0
  end

  # The complement: the fieldset stays out of the way on a first visit, which is
  # the reason it was collapsed in the first place.
  def test_ui_003_the_permissions_fieldset_should_stay_collapsed_on_a_fresh_form
    get :new_personal_access_token

    assert_response :success
    assert_select 'fieldset#personal-access-token-permissions.collapsed'
  end

  # UI-006. The hint under Expires reused the administrator's settings string,
  # which describes a control the user cannot see and offers an option this
  # select does not contain.
  def test_ui_006_the_expiry_hint_should_be_written_for_the_user_not_the_administrator
    with_settings :personal_access_token_max_lifetime_days => '90' do
      get :new_personal_access_token

      assert_response :success
      assert_select 'em.info', :text => /requires tokens to expire within 90 days/
      assert_select 'em.info', {:text => /0 means no limit/, :count => 0}
    end
  end

  # UI-008. The list can hold several tokens, so a bare confirmation leaves the
  # user unsure which one went. Names have no format validation and the flash is
  # rendered html_safe, so the escaping half is pinned with the naming half --
  # the administration screen walked into exactly this trap.
  def test_ui_008_the_revoke_flash_should_name_the_token_and_escape_it
    token = PersonalAccessToken.create!(:user => User.find(2), :name => '<b>pwn</b>')

    delete :revoke_personal_access_token, :params => {:id => token.id}

    assert_redirected_to '/my/personal_access_tokens'
    assert_include '&lt;b&gt;pwn&lt;/b&gt;', flash[:notice]
    assert_not_include '<b>pwn</b>', flash[:notice]
  end

  def test_new_personal_access_token_should_default_to_thirty_days
    get :new_personal_access_token

    assert_response :success
    assert_select 'input#personal_access_token_name'
    assert_select 'select#personal_access_token_expires_in_days' do
      assert_select 'option[selected="selected"][value=?]', '30'
    end
  end

  def test_personal_access_tokens_should_list_the_users_tokens_only
    PersonalAccessToken.create!(:user => User.find(2), :name => 'mine')
    PersonalAccessToken.create!(:user => User.find(3), :name => 'someone else')
    get :personal_access_tokens

    assert_response :success
    assert_select 'table.list td.name', :text => 'mine'
    assert_select 'table.list td.name', :text => 'someone else', :count => 0
  end

  def test_create_personal_access_token
    assert_difference 'PersonalAccessToken.count' do
      post :create_personal_access_token, :params => {
        :personal_access_token => {:name => 'CI', :expires_in_days => '30'}
      }
    end
    assert_response :success

    token = PersonalAccessToken.order(:id => :desc).first
    assert_equal User.find(2), token.user
    assert_equal User.current.today + 30, token.expires_on
    # the value is shown exactly once, on a page of its own that names the
    # token it belongs to, so it cannot be confused with another one
    assert_select 'h2', :text => /CI/
    assert_select 'pre#personal-access-token-value', :text => /\Armpat_[0-9a-f]{40}\z/
    assert_select 'div[data-controller=?] a.copy-api-key-link', 'api-key-copy'
  end

  def test_create_personal_access_token_should_not_show_the_value_again
    post :create_personal_access_token, :params => {
      :personal_access_token => {:name => 'CI', :expires_in_days => '30'}
    }
    assert_select 'pre#personal-access-token-value'

    get :personal_access_tokens
    assert_response :success
    assert_select 'pre#personal-access-token-value', 0
    assert_select 'table.list td.name', :text => 'CI'
  end

  def test_create_personal_access_token_without_expiry
    post :create_personal_access_token, :params => {
      :personal_access_token => {:name => 'CI', :expires_in_days => ''}
    }
    assert_response :success
    assert_nil PersonalAccessToken.order(:id => :desc).first.expires_on
  end

  def test_create_personal_access_token_without_name_should_fail
    assert_no_difference 'PersonalAccessToken.count' do
      post :create_personal_access_token, :params => {
        :personal_access_token => {:name => '', :expires_in_days => '30'}
      }
    end
    assert_response :success
    assert_select '#errorExplanation'
    assert_select 'pre#personal-access-token-value', 0
    # the form is redisplayed rather than the list
    assert_select 'select#personal_access_token_expires_in_days'
  end

  def test_revoke_personal_access_token
    token = PersonalAccessToken.create!(:user => User.find(2), :name => 'CI')

    assert_difference 'PersonalAccessToken.count', -1 do
      delete :revoke_personal_access_token, :params => {:id => token.id}
    end
    assert_redirected_to '/my/personal_access_tokens'
  end

  def test_create_personal_access_token_losing_a_name_race_should_redisplay_the_form
    # two submissions of the same name can both pass the uniqueness validation
    # and race to the unique index behind it
    PersonalAccessToken.any_instance.stubs(:save).raises(
      ActiveRecord::RecordNotUnique.new('duplicate key')
    )

    post :create_personal_access_token, :params => {
      :personal_access_token => {:name => 'CI', :expires_in_days => '30'}
    }
    assert_response :success
    assert_select '#errorExplanation'
    assert_select 'pre#personal-access-token-value', 0
  end

  def test_create_personal_access_token_should_require_sudo_mode
    Redmine::SudoMode.stubs(:enabled?).returns(true)

    assert_no_difference 'PersonalAccessToken.count' do
      post :create_personal_access_token, :params => {
        :personal_access_token => {:name => 'CI', :expires_in_days => '30'}
      }
    end
    assert_response :success
    assert_select 'input#sudo_password'
  end

  def test_revoke_personal_access_token_should_require_sudo_mode
    token = PersonalAccessToken.create!(:user => User.find(2), :name => 'CI')
    Redmine::SudoMode.stubs(:enabled?).returns(true)

    assert_no_difference 'PersonalAccessToken.count' do
      delete :revoke_personal_access_token, :params => {:id => token.id}
    end
    assert_response :success
    assert_select 'input#sudo_password'
  end

  def test_new_personal_access_token_should_default_to_the_read_only_preset
    get :new_personal_access_token

    assert_response :success
    assert_select 'input#personal_access_token_scope_preset_read_only[checked=?]', 'checked'
    assert_select 'input#personal_access_token_scope_preset_full'
    assert_select 'input#personal_access_token_scope_preset_custom'
    # the advanced picker, one checkbox per permission
    assert_select 'input#personal_access_token_permissions_view_issues'
    assert_select 'input#personal_access_token_permissions_edit_issues'
  end

  def test_new_personal_access_token_should_not_offer_the_admin_scope_to_an_ordinary_user
    get :new_personal_access_token
    assert_response :success
    assert_select 'input#personal_access_token_permissions_admin', 0
  end

  def test_new_personal_access_token_should_offer_the_admin_scope_to_an_administrator
    @request.session[:user_id] = 1
    get :new_personal_access_token
    assert_response :success
    assert_select 'input#personal_access_token_permissions_admin'
  end

  def test_create_personal_access_token_with_the_read_only_preset
    assert_difference 'PersonalAccessToken.count' do
      post :create_personal_access_token, :params => {
        :personal_access_token => {:name => 'CI', :expires_in_days => '30',
                                   :scope_preset => 'read_only',
                                   :permissions => ['', 'admin']}
      }
    end
    assert_response :success

    token = PersonalAccessToken.order(:id => :desc).first
    # the preset wins over whatever the picker posted
    assert_equal PersonalAccessToken.read_only_permissions.sort, token.permissions.sort
    assert_not_includes token.permissions, :admin
  end

  def test_create_personal_access_token_with_a_custom_scope
    assert_difference 'PersonalAccessToken.count' do
      post :create_personal_access_token, :params => {
        :personal_access_token => {:name => 'CI', :expires_in_days => '30',
                                   :scope_preset => 'custom',
                                   :permissions => ['', 'view_issues', 'log_time']}
      }
    end
    assert_response :success
    assert_equal [:view_issues, :log_time],
                 PersonalAccessToken.order(:id => :desc).first.permissions
  end

  def test_create_personal_access_token_with_the_full_preset
    post :create_personal_access_token, :params => {
      :personal_access_token => {:name => 'CI', :expires_in_days => '30',
                                 :scope_preset => 'full'}
    }
    assert_response :success
    assert_nil PersonalAccessToken.order(:id => :desc).first.permissions
  end

  def test_create_personal_access_token_with_an_unknown_permission_should_redisplay_the_form
    assert_no_difference 'PersonalAccessToken.count' do
      post :create_personal_access_token, :params => {
        :personal_access_token => {:name => 'CI', :expires_in_days => '30',
                                   :scope_preset => 'custom',
                                   :permissions => ['view_issues', 'not_a_permission']}
      }
    end
    assert_response :success
    assert_select '#errorExplanation'
  end

  def test_create_personal_access_token_with_an_empty_custom_scope_should_redisplay_the_form
    assert_no_difference 'PersonalAccessToken.count' do
      post :create_personal_access_token, :params => {
        :personal_access_token => {:name => 'CI', :expires_in_days => '30',
                                   :scope_preset => 'custom', :permissions => ['']}
      }
    end
    assert_response :success
    assert_select '#errorExplanation'

    # the same submission without even the form's empty hidden field: a custom
    # scope naming nothing must be refused, not resolve to nil, which means
    # unrestricted
    assert_no_difference 'PersonalAccessToken.count' do
      post :create_personal_access_token, :params => {
        :personal_access_token => {:name => 'CI', :expires_in_days => '30',
                                   :scope_preset => 'custom'}
      }
    end
    assert_response :success
    assert_select '#errorExplanation'
  end

  # A create request that says nothing about scope must not be read as asking
  # for the widest credential there is. It gets what the form pre-selects, so a
  # submission with the radio stripped behaves exactly like the untouched form.
  def test_create_personal_access_token_without_a_preset_should_not_grant_full_access
    assert_difference 'PersonalAccessToken.count' do
      post :create_personal_access_token, :params => {
        :personal_access_token => {:name => 'CI', :expires_in_days => '30'}
      }
    end
    assert_response :success

    token = PersonalAccessToken.order(:id => :desc).first
    assert_not_nil token.permissions, 'a request that named no scope got full access'
    assert_equal PersonalAccessToken.read_only_permissions.sort, token.permissions.sort
  end

  # The same, with a picker selection but no preset: the posted list must not
  # become the scope by falling through the resolver's case.
  def test_create_personal_access_token_without_a_preset_should_ignore_a_posted_permission_list
    post :create_personal_access_token, :params => {
      :personal_access_token => {:name => 'CI', :expires_in_days => '30',
                                 :permissions => ['admin']}
    }
    assert_response :success

    token = PersonalAccessToken.order(:id => :desc).first
    assert_not_includes token.permissions, :admin
    assert_equal PersonalAccessToken.read_only_permissions.sort, token.permissions.sort
  end

  # An unrecognised preset used to fall through the resolver's case and be
  # treated as "custom", which made SCOPE_PRESETS decorative.
  def test_create_personal_access_token_with_an_unknown_preset_should_redisplay_the_form
    assert_no_difference 'PersonalAccessToken.count' do
      post :create_personal_access_token, :params => {
        :personal_access_token => {:name => 'CI', :expires_in_days => '30',
                                   :scope_preset => 'bogus',
                                   :permissions => ['admin']}
      }
    end
    assert_response :success
    assert_select '#errorExplanation'
    assert_select 'pre#personal-access-token-value', 0
  end

  def test_personal_access_tokens_should_show_the_scope_of_each_token
    PersonalAccessToken.create!(:user => User.find(2), :name => 'unscoped')
    PersonalAccessToken.create!(:user => User.find(2), :name => 'read only',
                                :scope_preset => 'read_only')
    PersonalAccessToken.create!(:user => User.find(2), :name => 'custom',
                                :scope_preset => 'custom',
                                :permissions => ['view_issues', 'edit_issues'])
    PersonalAccessToken.create!(:user => User.find(2), :name => 'one permission',
                                :scope_preset => 'custom',
                                :permissions => ['add_issues'])
    get :personal_access_tokens

    assert_response :success
    assert_select 'table.list td.scope', :text => 'Full access'
    assert_select 'table.list td.scope', :text => 'Read-only'
    assert_select 'table.list td.scope', :text => 'Custom (2 permissions)'
    assert_select 'table.list td.scope', :text => 'Custom (1 permission)'
  end

  def test_revoke_personal_access_token_of_another_user_should_respond_404
    token = PersonalAccessToken.create!(:user => User.find(3), :name => 'CI')

    assert_no_difference 'PersonalAccessToken.count' do
      delete :revoke_personal_access_token, :params => {:id => token.id}
    end
    assert_response :not_found
  end
end
