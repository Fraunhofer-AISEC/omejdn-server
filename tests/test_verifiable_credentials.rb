# frozen_string_literal: true
require 'test/unit'
require 'rack/test'
require 'webrick/https'
require_relative 'config_testsetup'
require_relative '../omejdn'
require_relative '../lib/token_helper'
require_relative '../lib/verifiable_credentials'

# TODO add fixed test vectors for each proof algorithm
class VerifiableCredentialsTest < Test::Unit::TestCase
  include Rack::Test::Methods

  def app
    Sinatra::Application
  end

  def setup
    TestSetup.setup
    @client = Client.find_by_id 'testClient'
    @user = User.find_by_id 'testUser'
    @token = TokenHelper.build_access_token @client, ['openid_claims'], TestSetup.config['host'], @user, {'omejdn'=>{'claimset_format'=>'w3cvc-jws'}}
  end

  def teardown
    TestSetup.teardown
  end

  def check_keys(keylist, hash)
    assert_equal keylist.sort, hash.keys.sort
  end

  def test_verifiable_credentials
    request_param = {
      'claims'=>{
        'c_token'=>{
          'email'=>{
            'value' => 'admin@example.com'
          }
        }
      },
      'uid' => 'example1234',
      'aud' => ['some audience']
    }
    post '/claims', request_param, { 'HTTP_AUTHORIZATION' => "Bearer #{@token}" }
    assert last_response.ok?
    response = JSON.parse last_response.body
    check_keys ['format', 'claimset'], response
    jwt = JWT.decode(response['claimset'], Server.load_key('verifiable_credentials').public_key, true, { algorithm: TestSetup.config['token']['algorithm'] })
    header = jwt[1]
    check_keys ["alg", "typ", "kid"], header
    vc_jwt = jwt[0]
    check_keys ["nbf", "exp", "iss", "jti", "sub", "aud", "vc"], vc_jwt

    assert       vc_jwt['nbf'] <= Time.new.to_i
    assert       vc_jwt['exp'] >  vc_jwt['nbf']
    assert_equal vc_jwt['iss'], TestSetup.config['verifiable_credentials']['issuer']
    assert       vc_jwt['jti']
    assert       vc_jwt['sub']
    assert_equal vc_jwt['aud'], request_param['aud']

    vc = vc_jwt['vc']
    check_keys ["@context", "type", "issuer", "issuanceDate", "expirationDate", "id", "issued", "validFrom", "validUntil", "credentialSubject", "proof"], vc
    assert_equal TestSetup.config['verifiable_credentials']['issuer'], vc['issuer']
    assert  DateTime.parse(vc['issuanceDate']).to_time.to_i < DateTime.parse(vc['expirationDate']).to_time.to_i
    assert_equal vc['type'], ['VerifiableCredential', 'OmejdnCredential']
    assert vc['@context'].include? "https://www.w3.org/2018/credentials/v1"
    # TODO: Validate Proof

    subject = vc['credentialSubject']
    check_keys ['uid','id','email'], subject
    #JSON.pretty_generate(vc).split("\n").each{|l| p l}
  end

end
