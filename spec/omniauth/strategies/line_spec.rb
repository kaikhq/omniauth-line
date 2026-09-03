require 'spec_helper'

describe OmniAuth::Strategies::Line do
  let(:request) { double('Request', :params => {}, :cookies => {}, :env => {}) }
  let(:app) { lambda { |_env| [200, {}, ['']] } }

  subject do
    args = ['channel_id', 'secret', @options || {}].compact
    OmniAuth::Strategies::Line.new(app, *args).tap do |strategy|
      allow(strategy).to receive(:request) {
        request
      }
    end
  end

  describe 'client options' do
    it 'should have correct name' do
      expect(subject.options.name).to eq('line')
    end

    it 'should have correct site' do
      expect(subject.options.client_options.site).to eq('https://api.line.me')
    end

    it 'should have correct authorize url' do
      expect(subject.options.client_options.authorize_url).to eq('https://access.line.me/oauth2/v2.1/authorize')
    end

    it 'should have correct token url' do
      expect(subject.options.client_options.token_url).to eq('/oauth2/v2.1/token')
    end

    it 'should build the authorize url on access.line.me' do
      expect(subject.client.authorize_url).to start_with('https://access.line.me/oauth2/v2.1/authorize')
    end

    it 'should build the token url on api.line.me' do
      expect(subject.client.token_url).to eq('https://api.line.me/oauth2/v2.1/token')
    end
  end

  describe 'authorize params' do
    it 'should forward LINE-specific options to the authorize request' do
      @options = { prompt: 'consent', bot_prompt: 'normal', ui_locales: 'zh-TW' }
      allow(subject).to receive(:session).and_return({})
      params = subject.authorize_params
      expect(params[:prompt]).to eq('consent')
      expect(params[:bot_prompt]).to eq('normal')
      expect(params[:ui_locales]).to eq('zh-TW')
    end

    it 'should not forward options outside the whitelist' do
      @options = { channel_secret: 'super-secret' }
      allow(subject).to receive(:session).and_return({})
      expect(subject.authorize_params).not_to have_key(:channel_secret)
    end
  end

  describe 'callback_url' do
    it 'should exclude the query string' do
      allow(subject).to receive(:full_host).and_return('https://example.com')
      allow(subject).to receive(:script_name).and_return('')
      expect(subject.callback_url).to eq('https://example.com/auth/line/callback')
    end

    it 'should prefer an explicitly configured redirect_uri' do
      @options = { redirect_uri: 'https://school.example.com/api/auth/line/callback' }
      expect(subject.callback_url).to eq('https://school.example.com/api/auth/line/callback')
    end
  end

  describe 'callback data' do
    let(:id_token) { 'header.payload.signature' }
    let(:access_token) do
      OAuth2::AccessToken.new(subject.client, 'access-token',
                              'id_token' => id_token, 'scope' => 'profile openid email')
    end

    let(:profile_response) do
      {
        'userId'        => 'U4af4980629abc',
        'displayName'   => 'Foo Bar',
        'pictureUrl'    => 'https://profile.line-scdn.net/abc.jpg',
        'statusMessage' => 'Developer'
      }
    end

    let(:verify_response) do
      {
        'iss'   => 'https://access.line.me',
        'sub'   => 'U4af4980629abc',
        'email' => 'foo@example.com'
      }
    end

    before do
      allow(subject).to receive(:access_token).and_return(access_token)

      stub_request(:get, 'https://api.line.me/v2/profile')
        .with(:headers => { 'Authorization' => 'Bearer access-token' })
        .to_return(:status => 200, :body => profile_response.to_json,
                   :headers => { 'Content-Type' => 'application/json' })

      stub_request(:post, 'https://api.line.me/oauth2/v2.1/verify')
        .with(:body => { 'id_token' => id_token, 'client_id' => 'channel_id' })
        .to_return(:status => 200, :body => verify_response.to_json,
                   :headers => { 'Content-Type' => 'application/json' })
    end

    describe 'uid' do
      it 'should return the userId from the profile' do
        expect(subject.uid).to eq('U4af4980629abc')
      end
    end

    describe 'info' do
      it 'should return the name' do
        expect(subject.info[:name]).to eq('Foo Bar')
      end

      it 'should return the image' do
        expect(subject.info[:image]).to eq('https://profile.line-scdn.net/abc.jpg')
      end

      it 'should return the description' do
        expect(subject.info[:description]).to eq('Developer')
      end

      it 'should return the email decoded from the id token' do
        expect(subject.info[:email]).to eq('foo@example.com')
      end
    end

    describe 'extra' do
      it 'should contain the id token' do
        expect(subject.extra[:id_token]).to eq(id_token)
      end
    end

    describe 'raw_info' do
      it 'should memoize the profile request' do
        2.times { subject.raw_info }
        expect(a_request(:get, 'https://api.line.me/v2/profile')).to have_been_made.once
      end

      it 'should convert connection timeouts into Timeout::Error' do
        stub_request(:post, 'https://api.line.me/oauth2/v2.1/verify').to_raise(Errno::ETIMEDOUT)
        expect { subject.raw_info }.to raise_error(Timeout::Error)
      end
    end

    context 'when no id token was issued' do
      let(:access_token) do
        OAuth2::AccessToken.new(subject.client, 'access-token', 'scope' => 'profile')
      end

      it 'should return no email' do
        expect(subject.info[:email]).to be_nil
      end

      it 'should not call the verify endpoint' do
        subject.info
        expect(a_request(:post, 'https://api.line.me/oauth2/v2.1/verify')).not_to have_been_made
      end

      it 'should omit the id token from extra' do
        expect(subject.extra).to eq({})
      end
    end

    context 'when the email scope was not granted' do
      let(:access_token) do
        OAuth2::AccessToken.new(subject.client, 'access-token',
                                'id_token' => id_token, 'scope' => 'profile openid')
      end

      it 'should return no email' do
        expect(subject.info[:email]).to be_nil
      end

      it 'should not call the verify endpoint' do
        subject.info
        expect(a_request(:post, 'https://api.line.me/oauth2/v2.1/verify')).not_to have_been_made
      end
    end

    context 'when the token response carries no scope field' do
      let(:access_token) do
        OAuth2::AccessToken.new(subject.client, 'access-token', 'id_token' => id_token)
      end

      it 'should still fetch the email' do
        expect(subject.info[:email]).to eq('foo@example.com')
      end
    end
  end
end
