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

class MyController < ApplicationController
  self.main_menu = false
  before_action :require_login
  # let user change user's password when user has to
  skip_before_action :check_password_change, :check_twofa_activation, :only => :password

  accept_api_auth :account

  before_action :deny_account_update_by_a_scoped_token, :only => :account

  require_sudo_mode :account, only: :put
  require_sudo_mode :reset_atom_key, :reset_api_key, :show_api_key, :destroy
  require_sudo_mode :create_personal_access_token, :revoke_personal_access_token

  helper :issues
  helper :personal_access_tokens
  helper :users
  helper :custom_fields
  helper :queries
  helper :activities

  def index
    page
    render :action => 'page'
  end

  # Show user's page
  def page
    @user = User.current
    @groups = @user.pref.my_page_groups
    @blocks = @user.pref.my_page_layout
  end

  # Edit user's account
  def account
    @user = User.current
    @pref = @user.pref
    if request.put?
      @user.safe_attributes = params[:user]
      @user.pref.safe_attributes = params[:pref]
      if @user.save
        @user.pref.save
        respond_to do |format|
          format.html do
            flash[:notice] = l(:notice_account_updated)
            redirect_to my_account_path
          end
          format.api  {render_api_ok}
        end
        return
      else
        respond_to do |format|
          format.html {render :action => :account}
          format.api  {render_validation_errors(@user)}
        end
      end
    end
  end

  # Destroys user's account
  def destroy
    @user = User.current
    unless @user.own_account_deletable?
      redirect_to my_account_path
      return
    end

    if request.post? && params[:confirm]
      @user.destroy
      if @user.destroyed?
        logout_user
        flash[:notice] = l(:notice_account_deleted)
      end
      redirect_to home_path
    end
  end

  # Manage user's password
  def password
    @user = User.current
    unless @user.change_password_allowed?
      flash[:error] = l(:notice_can_t_change_password)
      redirect_to my_account_path
      return
    end
    if request.post?
      if !@user.check_password?(params[:password])
        flash.now[:error] = l(:notice_account_wrong_password)
      elsif params[:password] == params[:new_password]
        flash.now[:error] = l(:notice_new_password_must_be_different)
      else
        @user.password, @user.password_confirmation = params[:new_password], params[:new_password_confirmation]
        @user.must_change_passwd = false
        if @user.save
          # The session token was destroyed by the password change, generate a new one
          session[:tk] = @user.generate_session_token
          Mailer.deliver_password_updated(@user, User.current)
          flash[:notice] = l(:notice_account_password_updated)
          redirect_to my_account_path
        end
      end
    end
    no_store
  end

  # Create a new feeds key
  def reset_atom_key
    if request.post?
      if User.current.atom_token
        User.current.atom_token.destroy
        User.current.reload
      end
      User.current.atom_key
      flash[:notice] = l(:notice_feeds_access_key_reseted)
    end
    redirect_to my_account_path
  end

  def show_api_key
    @user = User.current
  end

  # Create a new API key
  def reset_api_key
    if request.post?
      if User.current.api_token
        User.current.api_token.destroy
        User.current.reload
      end
      User.current.api_key
      flash[:notice] = l(:notice_api_access_key_reseted)
    end
    redirect_to my_account_path
  end

  def personal_access_tokens
    @user = User.current
    @personal_access_tokens = @user.personal_access_tokens.sorted
  end

  def new_personal_access_token
    @user = User.current
    # Read-only by default, for the same reason the form defaults to an expiry:
    # a credential that can write should be asked for, not arrived at.
    @personal_access_token =
      PersonalAccessToken.new(:expires_in_days => PersonalAccessToken.default_lifetime_in_days,
                              :scope_preset => PersonalAccessToken::SCOPE_PRESET_READ_ONLY)
  end

  def create_personal_access_token
    @user = User.current
    @personal_access_token = PersonalAccessToken.new(personal_access_token_params)
    @personal_access_token.user = @user
    saved =
      begin
        @personal_access_token.save
      rescue ActiveRecord::RecordNotUnique
        # Two submissions of the same name can both pass the uniqueness
        # validation and race to the index behind it; show the loser the form
        # rather than an error page.
        @personal_access_token.errors.add(:name, :taken)
        false
      end
    if saved
      # The value is rendered once, from memory, on a page of its own so that
      # it is unambiguously the token just created. It is never put in the
      # flash or the session, and only its digest is stored, so there is no
      # second chance to read it.
      @token_value = @personal_access_token.value
      flash.now[:notice] = l(:notice_personal_access_token_created)
      no_store
      render :created_personal_access_token
    else
      render :new_personal_access_token
    end
  end

  def revoke_personal_access_token
    token = User.current.personal_access_tokens.find_by_id(params[:id])
    return render_404 if token.nil?

    token.destroy
    flash[:notice] = l(:notice_personal_access_token_revoked)
    redirect_to my_personal_access_tokens_path
  end

  def update_page
    @user = User.current
    block_settings = params[:settings] || {}

    block_settings.each do |block, settings|
      @user.pref.update_block_settings(block, settings.to_unsafe_hash)
    end
    @user.pref.save
    @updated_blocks = block_settings.keys
  end

  # Add a block to user's page
  # The block is added on top of the page
  # params[:block] : id of the block to add
  def add_block
    @user = User.current
    @block = params[:block]
    if @user.pref.add_block @block
      @user.pref.save
      respond_to do |format|
        format.html {redirect_to my_page_path}
        format.js
      end
    else
      render_error :status => 422
    end
  end

  # Remove a block to user's page
  # params[:block] : id of the block to remove
  def remove_block
    @user = User.current
    @block = params[:block]
    @user.pref.remove_block @block
    @user.pref.save
    respond_to do |format|
      format.html {redirect_to my_page_path}
      format.js
    end
  end

  # Change blocks order on user's page
  # params[:group] : group to order (top, left or right)
  # params[:blocks] : array of block ids of the group
  def order_blocks
    @user = User.current
    @user.pref.order_blocks params[:group], params[:blocks]
    @user.pref.save
    head :ok
  end

  private

  # Editing your own account is not expressible in the vocabulary a token scope
  # is written in -- there is no permission for it -- so a scoped token cannot
  # carry consent for it, and a scope that named every permission there is would
  # still not name this one. Rather than let the narrowest read-only token
  # rewrite its owner's email address, which is a password-reset pivot, the
  # write is refused. Reads are unaffected, and an unscoped token behaves as it
  # did before. The equivalent hole is open for oauth scopes and is left alone:
  # closing it would change existing behaviour.
  def deny_account_update_by_a_scoped_token
    return true unless request.put? || request.patch?
    return true unless User.current.scoped_by_personal_access_token?

    render_error :message => l(:error_scoped_token_cannot_update_account), :status => 403
    false
  end

  def personal_access_token_params
    if params[:personal_access_token].present?
      params.require(:personal_access_token).permit(:name, :expires_in_days, :scope_preset, :permissions => [])
    else
      {}
    end
  end
end
