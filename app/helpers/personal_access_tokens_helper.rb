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

module PersonalAccessTokensHelper
  # Names what a token can do, read from what it actually stores rather than
  # from the preset it was created with. A token issued from the read-only
  # preset before a plugin added a read permission still reads as read-only,
  # because every permission it holds is one.
  def personal_access_token_scope_label(token)
    if !token.scoped?
      l(:label_personal_access_token_scope_full)
    elsif token.read_only?
      l(:label_personal_access_token_scope_read_only)
    else
      l(:label_personal_access_token_scope_custom_count, :count => token.permissions.size)
    end
  end

  # The expiry cell, saying what the date *means* rather than leaving the reader
  # to compare it with today and infer. An expired token answers 401 to every
  # request, and its row was otherwise identical to a live one -- while the
  # model keeps expired tokens precisely so their owner can see why one stopped
  # working, which only works if the screen says so.
  def personal_access_token_expiry_label(token)
    return l(:label_expiration_none) if token.expires_on.blank?

    date = format_date(token.expires_on)
    return date unless token.expired?

    content_tag(:span, "#{date} (#{l(:label_personal_access_token_expired)})",
                :class => 'expired')
  end

  # Row class, so an expired token is marked as a state rather than only as a
  # date -- the same way Redmine marks a locked user.
  def personal_access_token_row_class(token)
    ['personal-access-token', ('expired' if token.expired?)].compact.join(' ')
  end

  # The permissions behind that label, for the cell's title attribute.
  def personal_access_token_scope_title(token)
    return nil unless token.scoped?

    token.permissions.collect do |name|
      name == :admin ? l(:label_administration) : l_or_humanize(name, :prefix => 'permission_')
    end.sort.join(', ')
  end
end
