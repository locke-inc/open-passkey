# frozen_string_literal: true

Rails.application.routes.draw do
  mount OpenPasskey::Engine => "/passkey"

  get "/passkey.js", to: "static#passkey_js"
  get "/style.css", to: "static#style_css"
  root "static#index"
end
