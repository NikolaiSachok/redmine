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

# Administration view of the API audit log.
#
# It declares no accept_api_auth on purpose. A REST endpoint for the log is
# deferred: it is self-referential -- reading the log would be an API call that
# the log records -- and it concentrates who-did-what for every user in the
# installation, which deserves its own decision rather than arriving as a side
# effect of this one.
class ApiAuditEventsController < ApplicationController
  self.main_menu = false

  layout 'admin'
  before_action :require_admin

  helper :queries
  include QueriesHelper
  helper :api_audit_queries
  # Included as well as declared as a view helper: query_to_csv runs in the
  # controller, so without this the export would fall through to the generic
  # column formatting and print raw column values where the screen shows
  # labels.
  include ApiAuditQueriesHelper

  def index
    # The CSV export ignores the session query, like every other export in
    # Redmine: an export is built from the parameters it was asked with.
    use_session = !request.format.csv?
    retrieve_query(ApiAuditQuery, use_session)

    if @query.valid?
      scope = @query.results_scope

      respond_to do |format|
        format.html do
          # The count is the expensive part of this screen and the reason the
          # query carries a default time window: this is the one table in the
          # installation with no upper bound on its size.
          @event_count = scope.count
          @limit = per_page_option
          @event_pages = Paginator.new @event_count, @limit, params['page']
          @events = scope.limit(@limit).offset(@event_pages.offset).to_a
          render :layout => !request.xhr?
        end
        format.csv do
          # Capped by the same setting as every other export, so a filter that
          # matches a year of traffic cannot be turned into an out-of-memory.
          @events = scope.limit(Setting.issues_export_limit.to_i).to_a
          send_data(query_to_csv(@events, @query, params),
                    :type => 'text/csv; header=present',
                    :filename => "#{filename_for_export(@query, 'api_audit')}.csv")
        end
      end
    else
      respond_to do |format|
        format.html {render :layout => !request.xhr?}
        format.csv {head :unprocessable_content}
      end
    end
  end
end
