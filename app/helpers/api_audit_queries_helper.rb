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
  # A cell whose first character is =, +, - or @ is evaluated as a formula by
  # Excel, LibreOffice and Google Sheets when the exported file is opened. Tab
  # and carriage return are here because both are stripped by the spreadsheet
  # before the prefix is looked at.
  CSV_FORMULA_PREFIX = /\A[=+\-@\t\r]/

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

  # Every cell of this export goes out through here, and every cell of it is
  # neutralised against spreadsheet formula injection.
  #
  # Two columns are user-controlled, which is the fact the first version of this
  # reasoning got wrong by enumerating columns rather than naming provenance:
  #
  # * +personal_access_token+ renders +PersonalAccessToken#name+, which is
  #   validated for presence, length and uniqueness and for **no format at all**
  #   -- so any user who can create a token can choose those bytes;
  # * +login+ is the login stored on the row, which is deliberately kept as text
  #   rather than read back through the account, so it is whatever the login was
  #   when the call happened.
  #
  # The remaining columns come from the route table, +request.path+, a known
  # verb, an integer, an IP, a formatted timestamp or a translated label. They
  # are neutralised anyway: an enumeration is only as good as its completeness,
  # and this one has already been wrong once.
  #
  # Scoped to this export rather than to +Redmine::Export::CSV+, which every
  # export in the product shares. Changing the shared generator would alter
  # behaviour well outside this slice; the alternative -- validating the format
  # of token names -- would take away a naming freedom users already have, to
  # fix a problem that lives in the reader rather than in the name.
  def csv_value(column, object, value)
    return super unless object.is_a?(ApiAuditEvent)

    cell =
      case column.name
      when :credential_type
        api_audit_credential_label(value)
      when :personal_access_token
        api_audit_token_label(object)
      else
        super
      end
    neutralize_csv_formula(cell)
  end

  # Prefixes a formula-leading cell with an apostrophe, which every major
  # spreadsheet reads as "the rest of this cell is text". The value stays
  # legible to a human reading the file, which stripping the character would
  # not.
  def neutralize_csv_formula(value)
    return value unless value.is_a?(String) && value.match?(CSV_FORMULA_PREFIX)

    "'#{value}"
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
