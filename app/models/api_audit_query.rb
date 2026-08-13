# frozen_string_literal: true

# Redmine - project management software
# Copyright (C) Jean-Philippe Lang
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

# Filtering, sorting and CSV export for the API audit log, through Redmine's
# own query machinery rather than a hand-rolled search form. UserQuery is the
# closest precedent: an administration-only query over a table that is not a
# project.
#
# Two things about it are specific to an audit log:
#
# * **It is administrators only, in both directions** -- the visible scope
#   returns nothing to anybody else, and so does visible? on a saved query. The
#   log concentrates who-did-what for every user in the installation.
# * **It defaults to a time window.** Redmine's list pattern runs COUNT(*) on
#   every page view (admin_controller.rb:40), and this is the one table in the
#   installation that grows without an upper bound. The default filter is what
#   keeps the default screen from scanning all of it.
class ApiAuditQuery < Query
  self.layout = 'admin'
  self.queried_class = ApiAuditEvent

  # How far back the screen looks when nobody has said otherwise, in days.
  DEFAULT_WINDOW_IN_DAYS = 7

  TABLE = ApiAuditEvent.table_name

  self.available_columns = [
    QueryColumn.new(:created_on, :sortable => "#{TABLE}.created_on", :default_order => 'desc', :caption => :label_api_audit_time),
    QueryColumn.new(:login, :sortable => "#{TABLE}.login", :caption => :field_login),
    QueryColumn.new(:impersonator_login, :sortable => "#{TABLE}.impersonator_login", :caption => :label_api_audit_impersonator),
    QueryColumn.new(:credential_type, :sortable => "#{TABLE}.credential_type", :groupable => "#{TABLE}.credential_type", :caption => :label_api_audit_credential),
    QueryColumn.new(:personal_access_token, :caption => :label_personal_access_token),
    QueryColumn.new(:http_method, :sortable => "#{TABLE}.http_method", :groupable => "#{TABLE}.http_method", :caption => :label_api_audit_method),
    QueryColumn.new(:endpoint, :sortable => "#{TABLE}.endpoint", :groupable => "#{TABLE}.endpoint", :caption => :label_api_audit_endpoint),
    QueryColumn.new(:path, :sortable => "#{TABLE}.path", :caption => :label_api_audit_path),
    QueryColumn.new(:status, :sortable => "#{TABLE}.status", :groupable => "#{TABLE}.status", :caption => :label_api_audit_status),
    QueryColumn.new(:ip, :sortable => "#{TABLE}.ip", :caption => :label_api_audit_ip)
  ]

  def self.visible(*args)
    user = args.shift || User.current
    if user&.admin?
      where('1=1')
    else
      where('1=0')
    end
  end

  def initialize(attributes=nil, *args)
    super(attributes)
    # A default the screen can override but never simply lacks: an unfiltered
    # first page would count and sort the whole table.
    self.filters ||= {'created_on' => {:operator => '>t-', :values => [DEFAULT_WINDOW_IN_DAYS.to_s]}}
  end

  def initialize_available_filters
    add_available_filter 'created_on', :type => :date_past, :label => :label_api_audit_time
    add_available_filter 'login', :type => :string, :label => :field_login
    add_available_filter 'impersonator_login', :type => :string, :label => :label_api_audit_impersonator
    add_available_filter 'credential_type',
                         :type => :list_optional,
                         :label => :label_api_audit_credential,
                         :values => lambda {credential_type_values}
    add_available_filter 'http_method',
                         :type => :list_optional,
                         :label => :label_api_audit_method,
                         :values => lambda {http_method_values}
    add_available_filter 'endpoint', :type => :string, :label => :label_api_audit_endpoint
    add_available_filter 'path', :type => :string, :label => :label_api_audit_path
    add_available_filter 'status', :type => :integer, :label => :label_api_audit_status
    add_available_filter 'ip', :type => :string, :label => :label_api_audit_ip
  end

  def visible?(user=User.current)
    user&.admin?
  end

  def editable_by?(user)
    user&.admin?
  end

  # The vocabulary the recorder writes, not a SELECT DISTINCT over the table:
  # the values are a fixed list in ApiAuditEvent, and a distinct scan of the
  # largest table in the installation to populate a dropdown is the kind of
  # query this class exists to avoid.
  def credential_type_values
    ApiAuditEvent::CREDENTIAL_TYPES.map {|type| [l("label_api_audit_credential_#{type}"), type]}
  end

  def http_method_values
    %w(GET POST PUT PATCH DELETE HEAD OPTIONS).map {|method| [method, method]}
  end

  # The token is in the default set, not merely available. credential_type says
  # only *that* a token was used; "which one" is the first question an
  # administrator asks, and a default view that cannot answer it fails the
  # purpose of auditing credential usage. base_scope already preloads the
  # association, so the cost was being paid for a column nobody was shown.
  def default_columns_names
    @default_columns_names ||= [:created_on, :login, :impersonator_login, :credential_type, :personal_access_token, :http_method, :endpoint, :status, :ip]
  end

  def default_sort_criteria
    [['created_on', 'desc']]
  end

  def base_scope
    ApiAuditEvent.where(statement).includes(:user, :impersonator, :personal_access_token)
  end

  def results_scope(options={})
    order_option = [group_by_sort_order, (options[:order] || sort_clause)].flatten.reject(&:blank?)

    base_scope.
      order(order_option).
      joins(joins_for_order_statement(order_option.join(',')))
  end
end
