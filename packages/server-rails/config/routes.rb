# frozen_string_literal: true

OpenPasskey::Engine.routes.draw do
  post "register/begin",  to: "passkey#begin_registration"
  post "register/finish", to: "passkey#finish_registration"
  post "login/begin",     to: "passkey#begin_authentication"
  post "login/finish",    to: "passkey#finish_authentication"
end
