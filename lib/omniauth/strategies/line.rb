require 'omniauth-oauth2'
require 'json'
require 'net/http'

module OmniAuth
  module Strategies
    class Line < OmniAuth::Strategies::OAuth2
      option :name, 'line'
      option :scope, 'profile openid'

      # Authorization lives on access.line.me while every API call
      # (token exchange, profile, verify) lives on api.line.me.
      option :client_options, {
        site: 'https://api.line.me',
        authorize_url: 'https://access.line.me/oauth2/v2.1/authorize',
        token_url: '/oauth2/v2.1/token'
      }

      uid { raw_info['userId'] }

      info do
        {
          name:        raw_info['displayName'],
          image:       raw_info['pictureUrl'],
          description: raw_info['statusMessage'],
          email:       raw_info['email']
        }
      end

      extra do
        hash = {}
        hash[:id_token] = access_token['id_token'] if access_token['id_token']

        hash
      end

      # LINE returns the email claim only inside the ID token (email scope),
      # never from the profile endpoint; the verify endpoint decodes it.
      def email
        id_token = access_token['id_token']
        scope = access_token['scope']
        return nil unless id_token
        # Skip the verify call when the granted scope is known to lack email;
        # a response without a scope field falls through and still tries.
        return nil if scope && !scope.split.include?('email')

        params = {
          id_token: id_token,
          client_id: client.id
        }

        response = Net::HTTP.post_form(URI('https://api.line.me/oauth2/v2.1/verify'), params)
        JSON.parse(response.body)['email']
      end

      # Require: Access token with PROFILE permission issued.
      def raw_info
        @raw_info ||= begin
          profile = JSON.parse(access_token.get('v2/profile').body)
          profile['email'] = email
          profile
        end
      rescue ::Errno::ETIMEDOUT
        raise ::Timeout::Error
      end

      def callback_url
        full_host + script_name + callback_path
      end
    end
  end
end
