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

# Answers the CORS preflight request that a browser sends before a
# cross-origin API call that carries a custom header such as X-Redmine-API-Key.
#
# The route is a catch-all for OPTIONS on API paths, so this controller never
# looks at what the path points to. That is deliberate on two counts: a
# preflight is a question about the origin, not about the resource, and
# answering it identically for every path means it cannot be used to enumerate
# which resources exist or which ones the caller would be allowed to read. The
# real request that follows is authenticated and authorised as it always was.
class CorsController < ApplicationController
  # A preflight is sent by the browser without credentials, without a session
  # cookie and without a CSRF token, so none of the usual gates can apply.
  skip_before_action :verify_authenticity_token
  skip_before_action :session_expiration, :check_if_login_required, :check_password_change, :check_twofa_activation

  def preflight
    # set_cors_headers has already decided whether the origin is allowed. When
    # it is not -- or when the feature is off, or the REST API is disabled --
    # nothing was set and the route behaves as if it did not exist, which is
    # what an OPTIONS request to Redmine did before this feature.
    return render_404 if response.headers['Access-Control-Allow-Origin'].blank?

    response.headers['Access-Control-Allow-Methods'] = Redmine::Cors::ALLOWED_METHODS
    response.headers['Access-Control-Allow-Headers'] = Redmine::Cors::ALLOWED_HEADERS
    response.headers['Access-Control-Max-Age'] = Redmine::Cors::MAX_AGE
    head :no_content
  end
end
