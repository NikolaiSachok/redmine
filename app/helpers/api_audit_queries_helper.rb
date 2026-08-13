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

module ApiAuditQueriesHelper
  def column_value(column, object, value)
    if object.is_a?(ApiAuditEvent)
      case column.name
      when :login
        api_audit_user_link(object.user, value)
      when :impersonator_login
        api_audit_user_link(object.impersonator, value)
      when :credential_type
        api_audit_credential_label(value)
      when :personal_access_token
        api_audit_token_label(object)
      else
        super
      end
    else
      super
    end
  end

  def csv_value(column, object, value)
    if object.is_a?(ApiAuditEvent)
      case column.name
      when :credential_type
        api_audit_credential_label(value)
      when :personal_access_token
        api_audit_token_label(object)
      else
        super
      end
    else
      super
    end
  end

  # The stored login is what is shown, and the account is only used to link to
  # it. A deleted user still has to read as the user who acted -- an audit
  # trail that empties itself when the account goes is worth nothing at the
  # moment it is needed.
  # Values are returned unescaped on purpose: column_content wraps them in
  # content_tag, which escapes anything not already marked html_safe, and the
  # same methods feed the CSV export where escaping would be wrong.
  def api_audit_user_link(user, login)
    return '' if login.blank?

    user ? link_to(login, user_path(user)) : login
  end

  def api_audit_credential_label(value)
    return '' if value.blank?

    key = "label_api_audit_credential_#{value}"
    ::I18n.exists?(key) ? l(key) : value
  end

  # The token's name if the row is still there, otherwise its id. Never its
  # value: only a digest of that is stored, and not in this table.
  def api_audit_token_label(event)
    return '' if event.personal_access_token_id.blank?

    token = event.personal_access_token
    token ? token.name : "##{event.personal_access_token_id}"
  end
end
