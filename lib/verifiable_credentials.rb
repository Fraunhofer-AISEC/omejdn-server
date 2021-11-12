# frozen_string_literal: true

require_relative './config'
require_relative './token_helper'
require 'json'
require 'set'
require 'securerandom'
require 'base64'
require 'digest'
require 'json/ld/signature'
require 'rbnacl'

module ProofType
  JWT_SIGNATURE = {
    'format' => 'JWT'
  }
  #LDP_RSA = {
  #  'format' => 'LDP',
  #  'type' => 'RsaSignature2018',
  #  'digest' => 'sha256',
  #  'digest_target' => 'ALL_MESSAGES'
  #}
  LDP_ED25519 = {
    'format' => 'LDP',
    'type' => 'Ed25519Signature2018',
    'digest' => 'sha256',
    'digest_target' => 'ALL_MESSAGES'
    # already included in credential context
    #'context' => 'https://w3id.org/security/suites/ed25519-2018/v1'
  }
  LDP_BBSPLUS = {
    'format' => 'LDP',
    'type' => 'BbsBlsSignature2020',
    'digest' => 'BLAKE2b512',
    'digest_target' => 'EACH_MESSAGE',
    'context' => 'https://w3id.org/security/suites/bls12381-2020/v1'
  }
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

  def self.normalize_urdna2015(input)
    graph = RDF::Graph.new << JSON::LD::API.toRdf(input)
    graph.dump(:normalize)
  end

  # This function adds a JSON-LD Proof to a JSON-LD object
  # Heavily inspired by https://github.com/johncallahan/ruby-jsonld-signatures (MIT License)
  # TODO: add privacy signatures
  def self.add_proof(vc, proof_type)
    # Generate options here
    # following https://github.com/transmute-industries/verifiable-data
    # Careful: Some options have to be adapted for older proof types
    vc['@context'] << proof_type['context'] unless proof_type['context'].nil?
    options = {
      # Additional contexts should not matter after normalization
      '@context' => vc['@context'],
      'type' => proof_type['type'],
      'nonce' => Base64.urlsafe_encode64(rand(2**64).to_s),
      'created' => Time.now.iso8601,
      'verificationMethod' => vc['issuer'],
      'proofPurpose' => 'assertionMethod'
    }

    # 1. Create a copy of document, hereafter referred to as output. (vc_clone in our code)
    vc_clone = vc.clone
    # May contain other proofs which shall be excluded from signing
    vc_clone.delete('proof')
    
    # 2. Generate a canonicalized document by canonicalizing document according to a canonicalization algorithm
    # All algorithms used here use URDNA2015 for normalization
    normalizedGraph = normalize_urdna2015 vc_clone
    normalizedGraph.split("\n").each {|l| p l}

    # 3. Create a value tbs that represents the data to be signed,
    #    and set it to the result of running the Create Verify Hash Algorithm,
    #    passing the information in options. 
    # 3.1. - 3.3. just form the options
    # 3.4. Generate output by: 
    # 3.4.1. Creating a canonicalized options document by canonicalizing options according to the canonicalization algorithm
    normalizedOptions = normalize_urdna2015 options
    case proof_type['digest_target']
    when 'ALL_MESSAGES'
      # 3.4.2. Hash canonicalized options document using the message digest algorithm (e.g. SHA-256) and set output to the result.
      tbs = OpenSSL::Digest.digest(proof_type['digest'], normalizedOptions)
      # 3.4.3. Hash canonicalized document using the message digest algorithm (e.g. SHA-256) and append it to output. 
      tbs << OpenSSL::Digest.digest(proof_type['digest'], normalizedGraph)
      # 3.5. - 3.6 are just notes
    when 'EACH_MESSAGE'
      # BBS requires splitting the data into messages
      # and not hashing them
      tbs =  normalizedOptions.split("\n")
      tbs += normalizedGraph.split("\n")
    end

    # 4. Digitally sign tbs using the privateKey and the the digital proof algorithm
    #    The resulting string is the proofValue.
    filename = Config.base_config.dig('verifiable_credentials','signing_keys',proof_type['type'])
    return if filename.nil? || !(File.exist? filename)
    proof = case proof_type
    when ProofType::LDP_BBSPLUS
      key  = OpenSSL::PKey::RSA.new File.read(filename)
      {'proofValue'=>(Base64.strict_encode64 (key.sign OpenSSL::Digest::SHA256.new, tbs))}
      
    when ProofType::LDP_ED25519
      # OpenSSL for Ruby should get support for ED25519 soon...
      #key  = OpenSSL::PKey::EC.new File.read(filename)
      # For now we may use the rbnacl gem
      # TODO check if this loads the OpenSSL PEM key correctly
      seed = p [File.readlines(filename).map(&:chomp)[1]].pack("H*")
      key = RbNaCl::SigningKey.new seed
      # The example at https://w3c-ccg.github.io/lds-ed25519-2018/ uses 'EdDSA' instead of 'ED25519'
      # No standard could be found, but Ruby's JWT only supports this
      {'jws'=>(JWT.encode tbs.bytes, key, 'ED25519', {"alg":"EdDSA","b64":false,"crit":["b64"]})}
    end

    # 5. Add a proof node to output containing a linked data proof using the appropriate type and proofValue values
    #    as well as all of the data in the proof options
    options.delete('@context')
    proof.merge!(options)
    (vc['proof'] ||= []) << proof
  end

  def self.get_vc_no_proof(subject, attributes, claims)
    # verify each claim
    verified_claims = claims.select { |k, v| verify_claim(attributes, k, v) }
    now = Time.new
    host = Config.base_config['host']

    vc = {}
    #vc['@context'] = ['https://www.w3.org/2018/credentials/v1', "#{host}/vc/context"]
    vc['@context'] = ['https://www.w3.org/2018/credentials/v1', {'email'=>'omejdn:email'}]
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
    proof_types.reject{|t|t['format'].equal? 'JWT'}.each { |proof| add_proof(vc, proof) }
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
