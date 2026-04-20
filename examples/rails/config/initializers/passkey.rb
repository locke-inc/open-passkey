# frozen_string_literal: true

OpenPasskey.configure do |c|
  c.rp_id = "localhost"
  c.rp_display_name = "Open Passkey Rails Example"
  c.origin = "http://localhost:3005"
  c.session = OpenPasskey::SessionConfig.new(
    secret: "rails-example-secret-must-be-32-chars!",
    secure: false
  )
end
