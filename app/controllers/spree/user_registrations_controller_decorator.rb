Spree::UserRegistrationsController.class_eval do
  def create
    build_resource(params[:user])
    check_for_promo
    if @user.save
      set_flash_message(:notice, :signed_up)
      sign_in(:user, @user)
      fire_event('spree.user.signup', :user => @user, :order => current_order(true))
      sign_in_and_redirect(:user, @user)
    else
      clean_up_passwords(@user)
      render :new
    end
    session[:omniauth] = nil unless @user.new_record?
  end

  private

  def build_resource(*args)
    super
    if session[:omniauth]
      @user.apply_omniauth(session[:omniauth])
      #@user.valid?
      @user
    end
  end

  def check_for_promo
    if @user.respond_to?(:signup_code) and !@user.signup_code.blank?
      if @user.signup_code.upcase != "DSFREE5"
        clean_up_passwords(@user)
        render :new
        session[:omniauth] = nil unless @user.new_record?
        return
      end
    end
  end
end
