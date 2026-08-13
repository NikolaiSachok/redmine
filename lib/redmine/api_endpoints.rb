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

module Redmine
  # Which REST API endpoints an administrator allows, at a finer grain than the
  # all-or-nothing +rest_api_enabled+ setting.
  #
  # An *endpoint* is a controller/action pair that declares +accept_api_auth+,
  # written as <tt>"controller_path#action"</tt>. That is exactly the pair
  # ApplicationController#accept_api_auth? already tests, so this adds no new
  # notion of what the API surface is -- it reuses the one the codebase has.
  #
  # Three properties are deliberate:
  #
  # * **The setting stores the _disabled_ list, never the enabled one.** An
  #   endpoint the setting has never seen -- a newly added core action, or a
  #   plugin's -- is therefore enabled, so an upgrade cannot silently break a
  #   running integration.
  # * **Stored values are only ever compared as strings.** Nothing here turns a
  #   stored value into a class name, a method name or a route lookup, and
  #   +Setting.rest_api_disabled_endpoints_from_params+ additionally intersects
  #   what the form posts with what was enumerated from the code, so a value
  #   that names no real endpoint cannot even be stored.
  # * **Enumeration never runs on the request path.** Deciding whether the
  #   current request is disabled is one Array#include? against a memoised
  #   Setting; walking the controllers is only done by the admin screen and
  #   when the setting is saved.
  module ApiEndpoints
    SEPARATOR = '#'

    class << self
      # Returns every known endpoint id, sorted by controller and then in the
      # order the controller declared its actions.
      def all
        grouped.flat_map do |controller, actions|
          actions.map {|action| id_for(controller, action)}
        end
      end

      # Returns {controller_path => [action, ...]} for every controller that
      # declares accept_api_auth.
      #
      # Nothing in the codebase enumerated accept_api_auth before this, so the
      # controllers have to be walked: eager_load! makes sure they are all
      # loaded in development, where they otherwise would not be, and
      # +descendants+ is the same technique Redmine::SubclassFactory already
      # uses to enumerate subclasses.
      def grouped
        Rails.application.eager_load!
        pairs =
          ApplicationController.descendants.filter_map do |klass|
            # anonymous controllers (tests build them) have no stable identity
            next if klass.name.blank? || klass.abstract?

            actions = klass.accept_api_auth.map(&:to_s).uniq
            next if actions.empty?

            [klass.controller_path, actions]
          end
        pairs.sort_by(&:first).to_h
      end

      def id_for(controller, action)
        "#{controller}#{SEPARATOR}#{action}"
      end

      # The configured disabled endpoints, normalised to an array of strings.
      #
      # A value of any other shape -- a leftover from a hand-edited database,
      # say -- disables nothing rather than disabling everything: this feature
      # takes API surface away, so an unreadable configuration must not be able
      # to take the API down.
      def disabled
        Array.wrap(Setting.rest_api_disabled_endpoints).map(&:to_s)
      end

      def disabled?(controller, action)
        disabled.include?(id_for(controller, action))
      end

      def enabled?(controller, action)
        !disabled?(controller, action)
      end
    end
  end
end
