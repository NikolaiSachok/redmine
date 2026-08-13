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

class RoutingApiAuditEventsTest < Redmine::RoutingTest
  def test_api_audit_events
    should_route 'GET /api_audit_events' => 'api_audit_events#index'
    should_route 'GET /api_audit_events.csv' => 'api_audit_events#index', :format => 'csv'
  end

  def test_the_log_should_have_no_api_representation
    # Deferred deliberately: a REST endpoint for the audit log is
    # self-referential and privacy-sensitive. The route constraint is what
    # makes that a fact rather than an omission.
    assert_raise ActionController::RoutingError do
      Rails.application.routes.recognize_path('/api_audit_events.json', :method => :get)
    end
    assert_raise ActionController::RoutingError do
      Rails.application.routes.recognize_path('/api_audit_events.xml', :method => :get)
    end
  end

  def test_the_log_should_not_be_writable
    assert_raise ActionController::RoutingError do
      Rails.application.routes.recognize_path('/api_audit_events', :method => :post)
    end
    assert_raise ActionController::RoutingError do
      Rails.application.routes.recognize_path('/api_audit_events/1', :method => :delete)
    end
  end
end
