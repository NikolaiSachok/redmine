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

require_relative '../../../test_helper'

class Redmine::CorsTest < ActiveSupport::TestCase
  def test_normalize_should_accept_an_origin_serialisation
    assert_equal 'https://example.com', Redmine::Cors.normalize('https://example.com')
    assert_equal 'http://example.com', Redmine::Cors.normalize('http://example.com')
    assert_equal 'https://example.com:8443', Redmine::Cors.normalize('https://example.com:8443')
    assert_equal 'http://localhost:3000', Redmine::Cors.normalize('http://localhost:3000')
    assert_equal 'http://[::1]:3000', Redmine::Cors.normalize('http://[::1]:3000')
    assert_equal 'https://xn--e1afmkfd.example', Redmine::Cors.normalize('https://xn--e1afmkfd.example')
  end

  def test_normalize_should_smooth_over_whitespace_case_and_a_trailing_slash
    assert_equal 'https://example.com', Redmine::Cors.normalize('  https://example.com  ')
    assert_equal 'https://example.com', Redmine::Cors.normalize('HTTPS://Example.COM')
    assert_equal 'https://example.com', Redmine::Cors.normalize('https://example.com/')
  end

  def test_normalize_should_reject_anything_that_is_not_an_origin
    [
      nil, '', '   ', '*', 'null', 'NULL', 'https://*.example.com', 'https://*',
      'example.com', '//example.com', 'ftp://example.com', 'file://', 'javascript:alert(1)',
      'https://example.com/path', 'https://example.com//', 'https://example.com?a=1',
      'https://example.com#f', 'https://user:pass@example.com', 'https://example.com:',
      'https://example.com:port', 'https://example.com:123456',
      'https://a.example.com https://b.example.com', "https://exam\nple.com"
    ].each do |value|
      assert_nil Redmine::Cors.normalize(value), "#{value.inspect} was accepted as an origin"
    end
  end

  def test_allowed_origins_should_be_empty_by_default
    assert_equal '', Setting.rest_api_cors_origins
    assert_equal [], Redmine::Cors.allowed_origins
    assert_not Redmine::Cors.enabled?
  end

  def test_allowed_origins_should_split_on_commas_and_drop_junk
    with_settings :rest_api_cors_origins => ' https://a.example.com , , null, *, https://b.example.com/ ,oops' do
      assert_equal ['https://a.example.com', 'https://b.example.com'], Redmine::Cors.allowed_origins
    end
  end

  def test_enabled_should_require_both_the_rest_api_and_an_origin
    with_settings :rest_api_enabled => '1', :rest_api_cors_origins => '' do
      assert_not Redmine::Cors.enabled?
    end
    with_settings :rest_api_enabled => '0', :rest_api_cors_origins => 'https://a.example.com' do
      assert_not Redmine::Cors.enabled?
    end
    with_settings :rest_api_enabled => '1', :rest_api_cors_origins => 'https://a.example.com' do
      assert Redmine::Cors.enabled?
    end
  end

  def test_allows_should_match_exactly
    with_settings :rest_api_cors_origins => 'https://app.example.com, http://localhost:3000' do
      assert Redmine::Cors.allows?('https://app.example.com')
      assert Redmine::Cors.allows?('http://localhost:3000')

      [
        nil, '', 'null', '*',
        'http://app.example.com', 'https://app.example.com:443', 'https://app.example.com:8443',
        'https://evil-app.example.com', 'https://app.example.com.evil.net',
        'https://app.example.co', 'https://app.example.como',
        'app.example.com', 'https://localhost:3000', 'http://localhost', 'http://localhost:30000',
        # A browser serialises an origin canonically, so these did not come
        # from one and are compared as they stand rather than normalised in.
        'https://app.example.com/', 'HTTPS://APP.EXAMPLE.COM', ' https://app.example.com'
      ].each do |origin|
        assert_not Redmine::Cors.allows?(origin), "#{origin.inspect} was allowed"
      end
    end
  end

  def test_allows_should_never_accept_null_even_if_configured
    with_settings :rest_api_cors_origins => 'null' do
      assert_equal [], Redmine::Cors.allowed_origins
      assert_not Redmine::Cors.allows?('null')
    end
  end

  def test_vary_with_origin
    assert_equal 'Origin', Redmine::Cors.vary_with_origin(nil)
    assert_equal 'Origin', Redmine::Cors.vary_with_origin('')
    assert_equal 'Accept, Origin', Redmine::Cors.vary_with_origin('Accept')
    assert_equal 'Accept, Accept-Encoding, Origin', Redmine::Cors.vary_with_origin('Accept, Accept-Encoding')
    assert_equal 'Origin', Redmine::Cors.vary_with_origin('Origin')
    assert_equal 'accept, origin', Redmine::Cors.vary_with_origin('accept, origin')
    assert_equal '*', Redmine::Cors.vary_with_origin('*')
  end

  # The whole design rests on never advertising credentials, so the constants
  # are asserted rather than left to a reviewer to notice.
  def test_the_policy_should_never_advertise_credentials_or_a_wildcard
    assert_not Redmine::Cors.const_defined?(:ALLOW_CREDENTIALS)
    assert_not_includes Redmine::Cors::ALLOWED_METHODS, '*'
    assert_not_includes Redmine::Cors::ALLOWED_HEADERS, '*'
  end

  # Nothing is reflected from the request, here either: a caller must not be
  # able to have an arbitrary header name exposed to itself.
  def test_exposed_headers_should_be_a_fixed_list_of_headers_redmine_sends
    assert_equal ['Location'], Redmine::Cors::EXPOSED_HEADERS.split(',').map(&:strip)
  end

  # allowed_origins is memoised against the setting string it was parsed from,
  # because enabled? and allows? both call it on every API request. The memo
  # has to disappear the instant the setting changes, in either direction.
  def test_allowed_origins_should_be_recomputed_when_the_setting_changes
    with_settings :rest_api_cors_origins => 'https://a.example.com' do
      assert_equal ['https://a.example.com'], Redmine::Cors.allowed_origins
      assert_same Redmine::Cors.allowed_origins, Redmine::Cors.allowed_origins
    end
    with_settings :rest_api_cors_origins => 'https://b.example.com' do
      assert_equal ['https://b.example.com'], Redmine::Cors.allowed_origins
    end
    with_settings :rest_api_cors_origins => '' do
      assert_equal [], Redmine::Cors.allowed_origins
    end
  end
end
