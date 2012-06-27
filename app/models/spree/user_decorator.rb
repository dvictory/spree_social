Spree::User.class_eval do
  has_many :user_authentications,:dependent => :destroy

  devise :omniauthable

  def apply_omniauth(omniauth)
    if omniauth['provider'] == "facebook"
      self.email = omniauth['info']['email'] if email.blank?
      self.first_name = omniauth['info']['first_name'] if first_name.blank?
      self.last_name = omniauth['info']['last_name'] if last_name.blank?
      #self.login = omniauth['info']['nickname'] if omniauth['info'].present?

    end
    user_authentications.build(:provider => omniauth['provider'], :uid => omniauth['uid'],:oauth_token => omniauth['credentials']['token'],:oauth_expires_at => Time.at(omniauth['credentials']['expires_at']))
  end

  def password_required?
    (user_authentications.empty? || !password.blank?) && super
  end
end
