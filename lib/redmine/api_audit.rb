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

module Redmine
  # Turns a finished request into an ApiAuditEvent row.
  #
  # **Why this is not an after_action.** Rails skips after_action callbacks
  # entirely when an earlier filter renders and halts the chain -- and the
  # refusals this log most needs are exactly those: the three rendered inside
  # user_setup (a revoked OAuth token, HTTP Basic while 2FA is active, an
  # unchanged password), require_login's 401, and the endpoint gate's 403. An
  # after_action would silently record everything except the authentication
  # failures the default level exists to capture. ApplicationController
  # therefore calls this from an +ensure+ around +process_action+, which no
  # filter ordering can skip and which still runs when the action raises.
  #
  # **Why it can never break a request.** Everything below is inside one rescue
  # that logs and returns nil. An audit trail that can take the product down is
  # a denial of service with good intentions.
  module ApiAudit
    class << self
      # Records the request the controller has just finished, if the log is on
      # and covers it. +exception+ is whatever is in flight in the caller's
      # ensure block, or nil.
      def record(controller, exception = nil)
        # First and cheapest: with the feature off this is one memoised
        # Setting read and nothing else happens on the request path.
        return nil unless ApiAuditEvent.recording?
        return nil unless audited?(controller)

        request = controller.request
        status = status_for(controller, exception)
        return nil unless ApiAuditEvent.records?(request.request_method, status, credential_rejected?(controller))

        ApiAuditEvent.create!(attributes_for(controller, request, status))
      rescue => e
        # Deliberately swallowed. The request has already been served; failing
        # to describe it must not change what the caller received.
        Rails.logger&.error("API audit logging failed: #{e.class}: #{e.message}")
        nil
      end

      # Whether this request is on the surface the log covers: the REST API,
      # plus anything an API credential was offered to.
      #
      # The last two clauses are not redundant with the first. accept_api_auth?
      # has no format check, so a credential in a header authenticates an
      # accept_api_auth action for an HTML request too -- and a credential that
      # was offered and *rejected* leaves no authenticated flag behind at all,
      # which is the one case an audit log must not miss.
      def audited?(controller)
        controller.api_request? ||
          controller.authenticated_by_api_credential? ||
          controller.api_credential_presented?
      end

      # A credential was offered and did not authenticate. That is an
      # authentication failure whatever status Redmine then chose to answer
      # with -- and for an HTML request it chooses 302 to the login form, which
      # is indistinguishable by status from a successful redirect.
      def credential_rejected?(controller)
        controller.api_credential_presented? && !controller.authenticated_by_api_credential?
      end

      # The status the caller actually received. When an exception escaped the
      # action, the response still holds its default, so the status is taken
      # from the exception the same way Rails' own exception middleware takes
      # it.
      def status_for(controller, exception)
        if exception
          ActionDispatch::ExceptionWrapper.status_code_for_exception(exception.class.name)
        else
          controller.response&.status.to_i
        end
      end

      private

      def attributes_for(controller, request, status)
        user = User.current if User.current&.logged?
        impersonator = controller.api_audit_impersonator

        {
          :user_id => user&.id,
          :login => ApiAuditEvent.clean(user&.login, User::LOGIN_LENGTH_LIMIT),
          :impersonator_id => impersonator&.id,
          :impersonator_login => ApiAuditEvent.clean(impersonator&.login, User::LOGIN_LENGTH_LIMIT),
          :credential_type => controller.api_audit_credential_type,
          # The token by id, whether it was accepted or refused. Its value
          # exists nowhere but the caller's own keeping -- only a digest of it
          # is stored, and not in this table.
          :personal_access_token_id => controller.api_audit_personal_access_token_id,
          :http_method => ApiAuditEvent.clean(request.request_method, 10),
          :endpoint => ApiAuditEvent.clean("#{controller.controller_path}##{controller.action_name}"),
          # request.path and never request.fullpath: the query string is where
          # a ?key= API key rides. Storing it would make this table the softest
          # place in the installation to steal every credential at once.
          :path => ApiAuditEvent.clean(request.path),
          :ip => ApiAuditEvent.clean(request.remote_ip, 45),
          :status => status,
          :created_on => Time.now
        }
      end
    end
  end
end
