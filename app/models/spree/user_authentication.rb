class Spree::UserAuthentication < ActiveRecord::Base
  attr_accessible :provider, :uid,:oauth_expires_at,:oauth_token
  belongs_to :user
end
