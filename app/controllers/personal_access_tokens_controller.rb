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

# Administration view of every user's personal access tokens.
#
# It deliberately shows no token value: only digests are stored, so there is
# nothing here for an administrator to read even by mistake.
class PersonalAccessTokensController < ApplicationController
  self.main_menu = false

  layout 'admin'
  before_action :require_admin

  require_sudo_mode :destroy

  def index
    scope = PersonalAccessToken.includes(:user).sorted
    @token_count = scope.count
    @token_pages = Paginator.new @token_count, per_page_option, params['page']
    @tokens = scope.limit(@token_pages.per_page).offset(@token_pages.offset).to_a
  end

  def destroy
    token = PersonalAccessToken.find(params[:id])
    token.destroy
    # Says whose token it was: this list holds every user's, so a bare
    # confirmation leaves the administrator unsure what they just revoked.
    # Both values are user-supplied and the flash is rendered html_safe, so
    # they are escaped here, as account_controller does for a registered mail.
    flash[:notice] = l(:notice_personal_access_token_revoked_for,
                       :name => ERB::Util.h(token.name),
                       :user => ERB::Util.h(token.user.to_s))
    redirect_to personal_access_tokens_path
  rescue ActiveRecord::RecordNotFound
    render_404
  end
end
