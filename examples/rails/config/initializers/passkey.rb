# frozen_string_literal: true

OpenPasskey.configure do |c|
  c.rp_id = "localhost"
  c.rp_display_name = "Open Passkey Rails Example"
  c.origin = "http://localhost:3005"
end
