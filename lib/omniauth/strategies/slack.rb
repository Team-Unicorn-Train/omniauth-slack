require 'omniauth/strategies/oauth2'
require 'uri'
require 'rack/utils'

module OmniAuth
  module Strategies
    class Slack < OmniAuth::Strategies::OAuth2
      option :name, 'slack'

      option :authorize_options, [:scope, :user_scope, :team]

      option :client_options, {
        site: 'https://slack.com',
        token_url: '/api/oauth.v2.access',
        authorize_url: '/oauth/v2/authorize'
      }

      option :auth_token_params, {
        mode: :query,
        param_name: 'token'
      }

      # User ID is not guaranteed to be globally unique across all Slack users.
      # The combination of user ID and team ID, on the other hand, is guaranteed
      # to be globally unique.
      uid { "#{user_identity['id']}-#{team_identity['id']}" }

      info do
        {
          team: { # Requires the team:read scope
            id: team_info.dig('team', 'id'),
            name: team_info.dig('team', 'name'),
            domain: team_info.dig('team', 'domain'),
            icon: team_info.dig('team', 'icon', 'image_102')
          },
          user: { # Requires the users:read scope
            id: user_info.dig('user', 'id'),
            name: user_info.dig('user', 'name'),
            real_name: user_info.dig('user', 'real_name'),
            email: user_info.dig('user', 'profile', 'email'),
            image: user_info.dig('user', 'profile', 'image_48'),
          }
        }
      end

      extra do
        {
          raw_info: {
            user_info: user_info,         # Requires the users:read scope
            team_info: team_info,         # Requires the team:read scope
            web_hook_info: web_hook_info,
            bot_info: bot_info
          }
        }
      end

      def authorize_params
        super.tap do |params|
          options[:authorize_options].each do |v|
            if request.params[v]
              params[v] = request.params[v.to_s]
            end
          end
        end
      end

      def identity
        @identity ||= access_token.get('/api/users.identity').parsed
      end

      def user_identity
        @user_identity ||= identity['user'].to_h
      end

      def team_identity
        @team_identity ||= identity['team'].to_h
      end

      def user_info
        url = URI.parse('/api/users.info')
        url.query = Rack::Utils.build_query(user: user_identity['id'])
        url = url.to_s

        @user_info ||= access_token.get(url).parsed
      end

      def team_info
        @team_info ||= access_token.get('/api/team.info').parsed
      end

      def web_hook_info
        return {} unless access_token.params.key? 'incoming_webhook'
        access_token.params['incoming_webhook']
      end

      def bot_info
        return {} unless access_token.params.key? 'bot'
        access_token.params['bot']
      end

      private

      def callback_url
        full_host + script_name + callback_path
      end
    end
  end
end
