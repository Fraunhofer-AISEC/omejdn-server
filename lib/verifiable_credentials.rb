# frozen_string_literal: true

require_relative './config'
require_relative './token_helper'
require 'json'
require 'set'
require 'securerandom'
require 'base64'
require 'digest'

module ProofType
  JWT_SIGNATURE = 0x01
  BBSPLUS = 0x02
end

class VerifiableCredentials
  def self.verify_claim(attributes, key, value)
    !(attributes.select do |attr|
        attr['key'] == key && attr['value'] == value
    end).empty?
  end

  def self.json_ld_context
    raise NotImplementedError
  end

  # TODO: add privacy signatures
  def self.add_proof(vc, proof_type)
    raise NotImplementedError
  end

  def self.get_vc_no_proof(subject, attributes, claims)
    # verify each claim
    verified_claims = claims.select { |k, v| verify_claim(attributes, k, v) }
    now = Time.new
    host = Config.base_config['host']

    vc = {}
    vc['@context'] = ['https://www.w3.org/2018/credentials/v1', "#{host}/vc/context"]
    vc['type'] = %w[VerifiableCredential OmejdnCredential]
    vc['issuer'] = Config.base_config['verifiable_credentials']['issuer']
    vc['issuanceDate'] = now.to_datetime.rfc3339(3)
    vc['expirationDate'] = (now + Config.base_config['verifiable_credentials']['expiration']).to_datetime.rfc3339(3)
    vc['id'] = "#{host}/vc/credentials/#{Base64.urlsafe_encode64(rand(2**64).to_s)}"

    # These are expected to be defined in a future version of https://www.w3.org/TR/vc-data-model
    # To make sure no one uses these claims for other purposes, we overwrite them here.
    vc['issued'] = vc['issuanceDate']
    vc['validFrom'] = vc['issuanceDate']
    vc['validUntil'] = vc['expirationDate']

    subj = verified_claims
    subj['id'] = "#{host}/vc/#{subject}"
    vc['credentialSubject'] = subj

    vc
  end

  def self.get_vc(subject, attributes, claims, proof_types)
    vc = get_vc_no_proof(subject, attributes, claims)
    (proof_types - [ProofType::JWT_SIGNATURE]).each { |proof| add_proof(vc, proof) }
    vc
  end

  def self.get_jwt(subject, attributes, claims, proof_types = [])
    proof_types |= []
    vc = get_vc(subject, attributes, claims, proof_types)

    payload = {}
    payload['nbf'] = DateTime.parse(vc['issuanceDate']).to_time.to_i
    payload['exp'] = DateTime.parse(vc['expirationDate']).to_time.to_i
    payload['iss'] = vc['issuer']
    payload['jti'] = vc['id']
    payload['sub'] = vc['credentialSubject']['id']
    payload['aud'] = subject
    payload['vc'] = vc

    if proof_types.include? ProofType::JWT_SIGNATURE
      key = Server.load_key('verifiable_credentials')
      alg = Config.base_config['verifiable_credentials']['algorithm']
      jwt = JWT.encode payload, key, alg, { typ: 'JWT', kid: 'default' }
    else
      jwt = JWT.encode payload, nil, 'none', { typ: 'JWT' }
    end
    jwt
  end
end
