require 'omniauth-oauth2'
require 'json'
require 'net/http'

module OmniAuth
  module Strategies
    class Line < OmniAuth::Strategies::OAuth2
      option :name, 'line'
      option :scope, 'profile openid'

      # omniauth-oauth2 only forwards options named here to the authorize
      # URL; anything else set on the strategy is silently dropped.
      option :authorize_options, %i[
        scope state prompt nonce max_age ui_locales bot_prompt
        initial_amr_display switch_amr disable_auto_login
        disable_ios_auto_login
      ]

      # The verify call runs inside the user-facing callback request, so a
      # slow LINE API must fail fast rather than hold the login hostage.
      option :verify_options, { open_timeout: 5, read_timeout: 10 }

      # Authorization lives on access.line.me while every API call
      # (token exchange, profile, verify) lives on api.line.me.
      # LINE documents only client_secret_post for the token endpoint; the
      # oauth2 gem's basic-auth default happens to work but is undocumented
      # LINE behavior.
      option :client_options, {
        site: 'https://api.line.me',
        authorize_url: 'https://access.line.me/oauth2/v2.1/authorize',
        token_url: '/oauth2/v2.1/token',
        auth_scheme: :request_body
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
      # Email is best-effort: any verify failure degrades to nil instead of
      # failing the whole login.
      def email
        id_token = access_token['id_token']
        scope = access_token['scope']
        return nil unless id_token
        # Skip the verify call when the granted scope is known to lack email;
        # a response without a scope field falls through and still tries.
        return nil if scope && !scope.split.include?('email')

        response = verify_id_token(id_token)
        payload = JSON.parse(response.body)
        unless response.is_a?(Net::HTTPSuccess)
          log :warn, "ID token verify failed (HTTP #{response.code}): #{payload['error_description'] || payload['error']}"
          return nil
        end
        payload['email']
      rescue Net::OpenTimeout, Net::ReadTimeout, Errno::ETIMEDOUT => e
        log :warn, "ID token verify timed out (#{e.class})"
        nil
      rescue JSON::ParserError
        log :warn, 'ID token verify returned a non-JSON body'
        nil
      end

      # Require: Access token with PROFILE permission issued.
      def raw_info
        @raw_info ||= begin
          profile = JSON.parse(access_token.get('v2/profile').body)
          profile['email'] = email
          profile
        end
      rescue ::OAuth2::TimeoutError, ::Errno::ETIMEDOUT
        # omniauth-oauth2's callback_phase only maps ::Timeout::Error and
        # ::Errno::ETIMEDOUT to fail!(:timeout); OAuth2::TimeoutError is a
        # Faraday subclass it would let escape as a 500.
        raise ::Timeout::Error
      end

      def callback_url
        options[:redirect_uri] || (full_host + script_name + callback_path)
      end

      private

      def verify_id_token(id_token)
        uri = URI('https://api.line.me/oauth2/v2.1/verify')
        request = Net::HTTP::Post.new(uri)
        request.set_form_data(id_token: id_token, client_id: client.id)
        Net::HTTP.start(uri.host, uri.port,
                        use_ssl: true,
                        open_timeout: options.verify_options[:open_timeout],
                        read_timeout: options.verify_options[:read_timeout]) do |http|
          http.request(request)
        end
      end
    end
  end
end
