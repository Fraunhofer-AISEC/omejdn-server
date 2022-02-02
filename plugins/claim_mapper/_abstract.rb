# frozen_string_literal: true

require 'abstraction'

# Abstract ClaimMapper interface
class ClaimMapper
  abstract

  def self.map_claims(claims, provider)
    raise NotImplementedError
  end
end
