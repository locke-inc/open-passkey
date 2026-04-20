# frozen_string_literal: true

class StaticController < ActionController::Base
  skip_forgery_protection
  SHARED_DIR = File.expand_path("../../../shared", __dir__)
  PUBLIC_DIR = File.expand_path("../../public", __dir__)

  def index
    send_file File.join(PUBLIC_DIR, "index.html"), disposition: :inline
  end

  def passkey_js
    send_file File.join(SHARED_DIR, "passkey.js"), type: "application/javascript", disposition: :inline
  end

  def style_css
    send_file File.join(SHARED_DIR, "style.css"), type: "text/css", disposition: :inline
  end
end
