Spree::User.class_eval do
  has_many :user_authentications,:dependent => :destroy

  devise :omniauthable

  def apply_omniauth(omniauth)
    user_authentications.build(:provider => omniauth['provider'], :uid => omniauth['uid'])
    if omniauth['provider'] == "facebook"
      self.email = omniauth[:info][:email] if omniauth[:info].present?
      self.login = omniauth[:info][:nickname] if omniauth[:info].present?
    end
  end

  def password_required?
    (user_authentications.empty? || !password.blank?) && super
  end
end
