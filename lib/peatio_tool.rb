class PeatioTool
  def encode_jwt(private_file, email)
    payload = {
      email: email,
      iss: ENV['JWT_ISSUER'].to_s.squish.presence,
      iat: Time.now.to_i,
      jti: SecureRandom.hex(20),
      sub: 'session',
      aud: ENV['JWT_AUDIENCE'].to_s.split(',').map(&:squish).reject(&:blank?).presence,
    }
    JWT.encode(payload, OpenSSL::PKey.read(Base64.urlsafe_decode64(File.read(Rails.root.join(private_file)).strip)), ENV.fetch('JWT_ALGORITHM'))
  end

  def decode_jwt(token)
    JWT.decode(token, jwt_public_key, true, token_verification_options)
    .tap { |pair| pair[0].symbolize_keys! }

  end

  def jwt_public_key
    OpenSSL::PKey.read(Base64.urlsafe_decode64(ENV.fetch('JWT_PUBLIC_KEY')))
  end

  def token_verification_options
    { verify_expiration: true,
      verify_not_before: true,
      # Set option only if it is not blank.
      iss:               ENV['JWT_ISSUER'].to_s.squish.presence,
      verify_iss:        ENV['JWT_ISSUER'].present?,
      verify_iat:        true,
      verify_jti:        true,
      # Support comma-separated JWT_AUDIENCE variable.
      # We are rejecting blank values from the list here.
      aud:               ENV['JWT_AUDIENCE'].to_s.split(',').map(&:squish).reject(&:blank?).presence,
      verify_aud:        ENV['JWT_AUDIENCE'].present?,
      sub:               'session',
      verify_sub:        true,
      algorithms:        [ENV.fetch('JWT_ALGORITHM')],
      leeway:            ENV['JWT_DEFAULT_LEEWAY'].to_s.squish.yield_self { |n| n.to_i if n.present? },
      iat_leeway:        ENV['JWT_ISSUED_AT_LEEWAY'].to_s.squish.yield_self { |n| n.to_i if n.present? },
      exp_leeway:        ENV['JWT_EXPIRATION_LEEWAY'].to_s.squish.yield_self { |n| n.to_i if n.present? },
      nbf_leeway:        ENV['JWT_NOT_BEFORE_LEEWAY'].to_s.squish.yield_self { |n| n.to_i if n.present? }
    }.compact
  end

end
