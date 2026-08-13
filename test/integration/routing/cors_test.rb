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

require_relative '../../test_helper'

# The CORS preflight route is a glob, which makes it the one route in Redmine
# whose *position* and *constraints* are load-bearing rather than incidental.
# should_route is not usable here: it only understands GET/POST/PUT/PATCH/DELETE.
class RoutingCorsTest < Redmine::RoutingTest
  def test_options_on_an_api_path_should_route_to_the_preflight
    assert_recognizes(
      {:controller => 'cors', :action => 'preflight', :resource => 'issues', :format => 'json'},
      {:path => '/issues.json', :method => :options}
    )
    assert_recognizes(
      {:controller => 'cors', :action => 'preflight', :resource => 'issues/1', :format => 'xml'},
      {:path => '/issues/1.xml', :method => :options}
    )
    assert_recognizes(
      {:controller => 'cors', :action => 'preflight', :resource => 'no/such/thing', :format => 'json'},
      {:path => '/no/such/thing.json', :method => :options}
    )
  end

  # The format constraint is anchored, so it is the extension and nothing else.
  def test_options_outside_the_api_formats_should_not_route
    ['/issues', '/issues.csv', '/issues.jsonp', '/issues.js', '/issues.JSON', '/issues.json.txt', '/'].each do |path|
      assert_raise(ActionController::RoutingError, "OPTIONS #{path} was routed") do
        Rails.application.routes.recognize_path(path, :method => :options)
      end
    end
  end

  # The glob must not swallow the real verbs on the same paths.
  def test_other_verbs_on_api_paths_should_be_unaffected
    should_route 'GET /issues.json' => 'issues#index', :format => 'json'
    should_route 'POST /issues.json' => 'issues#create', :format => 'json'
    should_route 'GET /issues/1.json' => 'issues#show', :id => '1', :format => 'json'
    should_route 'PUT /issues/1.json' => 'issues#update', :id => '1', :format => 'json'
    should_route 'DELETE /issues/1.json' => 'issues#destroy', :id => '1', :format => 'json'
    should_route 'GET /projects.xml' => 'projects#index', :format => 'xml'
  end

  # A glob route is never a sensible fallback for URL generation.
  def test_the_preflight_route_should_not_be_used_to_generate_urls
    assert_equal '/issues.json', Rails.application.routes.url_helpers.issues_path(:format => 'json')
    assert_equal '/issues/1.json', Rails.application.routes.url_helpers.issue_path(1, :format => 'json')
  end

  # CORS-012 from the attack ledger. A glob matches every path, so anything
  # drawn after it is unreachable for OPTIONS; the catch-all is therefore drawn
  # last in config/routes.rb, below the plugin routes loop. Both halves are
  # asserted: that it really is last in the routes this file defines, and that
  # in that order a plugin's own OPTIONS route on a .json path still wins.
  def test_cors_012_the_preflight_catch_all_does_not_shadow_a_later_route
    routes = Rails.application.routes.routes.to_a
    drawn_after = routes.drop(routes.index {|route| route.defaults[:controller] == 'cors'} + 1)
    assert_equal(
      [], drawn_after.reject {|route| route.defaults[:controller].to_s.start_with?('rails/')}.map {|route| route.path.spec.to_s},
      'routes are drawn after the CORS preflight glob, so it shadows them for OPTIONS'
    )

    # No plugins are installed here, so the loop that loads their routes
    # contributes nothing to the set above; the ordering in the file is what
    # decides whether a plugin route would be reachable.
    source = Rails.root.join('config/routes.rb').read
    assert_operator(
      source.index("match '*resource'"), :>, source.index('Redmine::Plugin.directory.glob'),
      'the CORS preflight glob must be drawn after the plugin routes loop'
    )

    set = ActionDispatch::Routing::RouteSet.new
    set.draw do
      match 'myplugin/thing', :to => 'issues#opts', :via => :options, :format => 'json'
      match '*resource', :to => 'cors#preflight', :via => :options, :format => true, :constraints => {:format => /json|xml/}
    end

    assert_equal 'issues', set.recognize_path('/myplugin/thing.json', :method => :options)[:controller]
    assert_equal 'cors', set.recognize_path('/myplugin/other.json', :method => :options)[:controller]
  end
end
