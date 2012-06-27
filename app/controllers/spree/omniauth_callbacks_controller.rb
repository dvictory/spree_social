class Spree::OmniauthCallbacksController < Devise::OmniauthCallbacksController
  include Spree::Core::CurrentOrder
  include Spree::Core::ControllerHelpers

  def self.provides_callback_for(*providers)
    providers.each do |provider|
      class_eval %Q{
        def #{provider}
          if request.env["omniauth.error"].present?
            flash[:error] = t("devise.omniauth_callbacks.failure", :kind => auth_hash['provider'], :reason => t(:user_was_not_valid))
            redirect_back_or_default(root_url)
            return
          end

          authentication = Spree::UserAuthentication.find_by_provider_and_uid(auth_hash['provider'], auth_hash['uid'])

          if authentication.present?
            flash[:notice] = "Signed in successfully"
            sign_in_and_redirect :user, authentication.user
          elsif current_user
            current_user.user_authentications.create!(:provider => auth_hash['provider'], :uid => auth_hash['uid'])
            flash[:notice] = "Authentication successful."
            redirect_back_or_default(account_url)
          else
            user = Spree::User.find_by_email(auth_hash['info']['email']) || Spree::User.new
            user.apply_omniauth(auth_hash)
            if user.save
              flash[:notice] = "Signed in successfully."
              sign_in_and_redirect :user, user
            else
              session[:omniauth] = auth_hash.except('extra')
              flash[:notice] = t(:one_more_step, :kind => auth_hash['provider'].capitalize)
              redirect_to new_user_registration_url
            end
          end

          if current_order
            user = current_user if current_user
            current_order.associate_user!(user)
            session[:guest_token] = nil
          end
        end
      }
    end
  end

  def facebook
    if request.env["omniauth.error"].present?
      flash[:error] = t("devise.omniauth_callbacks.failure", :kind => auth_hash['provider'], :reason => t(:user_was_not_valid))
      redirect_back_or_default(root_url)
      return
    end

    authentication = Spree::UserAuthentication.find_by_provider_and_uid(auth_hash['provider'], auth_hash['uid'])
    session[:fb_token] = auth_hash[:credentials][:token] if auth_hash[:credentials].present?
    if !authentication.nil?  #We already have an authentication
      authentication.oauth_token = auth_hash[:credentials][:token] if auth_hash[:credentials].present?
      authentication.oauth_token = auth_hash[:credentials][:expires_at] if auth_hash[:credentials].present?
      authentication.save
      #see if the current user is the one that has the authentication
      #sign in user if we are not signed it
      if current_user.nil?
        sign_in authentication.user, :event => :authentication
        @after_sign_in_url = after_sign_in_path_for(authentication.user)
        render 'callback', :layout => false
      elsif current_user and current_user.id == authentication.user.id
        flash[:notice] = "You have successfully linked your #{auth_hash['provider'].capitalize} account."
        sign_in authentication.user, :event => :authentication
        @after_sign_in_url = after_sign_in_path_for(authentication.user)
        render 'callback', :layout => false
      elsif current_user and current_user.id != authentication.user.id  #account already used
        flash[:info] = "The #{auth_hash['provider'].capitalize} account is already linked to another user account."
        @after_sign_in_url = account_url
        render 'callback', :layout => false

      else
        #Should never get here.
        flash[:info] = "Your #{auth_hash['provider'].capitalize} account is already linked with an account."
        session["user_return_to"] = nil
        @after_sign_in_url = login_url
        render 'callback', :layout => false

      end

    elsif current_user
      current_user.user_authentications.create!(:provider => auth_hash['provider'], :uid => auth_hash['uid'],:oauth_token=>auth_hash[:credentials][:token],:oauth_expires_at=>auth_hash[:credentials][:expires_at])
      flash[:notice] = "Account linking successful."
      @after_sign_in_url = account_url
      render 'callback', :layout => false

    else

      user = Spree::User.find_by_email(auth_hash['info']['email']) || Spree::User.new
      if user.new_record?
        session[:omniauth] = auth_hash.except('extra')
        flash[:info] = t(:one_more_step, :kind => auth_hash['provider'].capitalize)
        @after_sign_in_url = new_user_registration_url
        render 'callback', :layout => false
      else
        user.apply_omniauth(auth_hash)
        if user.save
          flash[:notice] = "Signed in successfully."
          sign_in user, :event => :authentication
          @after_sign_in_url = account_url
          render 'callback', :layout => false
        else
          session[:omniauth] = auth_hash.except('extra')
          flash[:info] = t(:one_more_step, :kind => auth_hash['provider'].capitalize)
          @after_sign_in_url = new_user_registration_url
          render 'callback', :layout => false
        end
      end

    end

    if current_order
      user = current_user if current_user
      current_order.associate_user!(user)
      session[:guest_token] = nil
    end
  end

  def twitter
    if request.env["omniauth.error"].present?
      flash[:error] = t("devise.omniauth_callbacks.failure", :kind => auth_hash['provider'], :reason => t(:user_was_not_valid))
      redirect_back_or_default(root_url)
      return
    end

    authentication = Spree::UserAuthentication.find_by_provider_and_uid(auth_hash['provider'], auth_hash['uid'])
    session[:fb_token] = auth_hash[:credentials][:token] if auth_hash[:credentials].present?
    if !authentication.nil?  #We already have an authentication
      #see if the current user is the one that has the authentication
      #sign in user if we are not signed it
      if current_user.nil?
        sign_in authentication.user, :event => :authentication
        @after_sign_in_url = after_sign_in_path_for(authentication.user)
        render 'callback', :layout => false
      elsif current_user and current_user.id == authentication.user.id
        flash[:notice] = "You have successfully linked your #{auth_hash['provider'].capitalize} account."
        sign_in authentication.user, :event => :authentication
        @after_sign_in_url = after_sign_in_path_for(authentication.user)
        render 'callback', :layout => false
      elsif current_user and current_user.id != authentication.user.id  #account already used
        flash[:info] = "The #{auth_hash['provider'].capitalize} account is already linked to another user account."
        @after_sign_in_url = account_url
        render 'callback', :layout => false

      else
        #Should never get here.
        flash[:info] = "Your #{auth_hash['provider'].capitalize} account is already linked with an account."
        session["user_return_to"] = nil
        @after_sign_in_url = login_url
        render 'callback', :layout => false

      end

    elsif current_user
      current_user.user_authentications.create!(:provider => auth_hash['provider'], :uid => auth_hash['uid'])
      flash[:notice] = "Account linking successful."
      @after_sign_in_url = account_url
      render 'callback', :layout => false

    else

      user = Spree::User.find_by_email(auth_hash['info']['email']) || Spree::User.new
      if user.new_record?
        session[:omniauth] = auth_hash.except('extra')
        flash[:info] = t(:one_more_step, :kind => auth_hash['provider'].capitalize)
        @after_sign_in_url = new_user_registration_url
        render 'callback', :layout => false
      else
        user.apply_omniauth(auth_hash)
        if user.save
          flash[:notice] = "Signed in successfully."
          sign_in user, :event => :authentication
          @after_sign_in_url = account_url
          render 'callback', :layout => false
        else
          session[:omniauth] = auth_hash.except('extra')
          flash[:info] = t(:one_more_step, :kind => auth_hash['provider'].capitalize)
          @after_sign_in_url = new_user_registration_url
          render 'callback', :layout => false
        end
      end

    end

    if current_order
      user = current_user if current_user
      current_order.associate_user!(user)
      session[:guest_token] = nil
    end
  end
  #SpreeSocial::OAUTH_PROVIDERS.each do |provider|
  #  provides_callback_for provider[1].to_sym
  #end

  def failure
    set_flash_message :alert, :failure, :kind => failed_strategy.name.to_s.humanize, :reason => failure_message
    redirect_to spree.login_path
  end

  def passthru
    render :file => "#{Rails.root}/public/404", :formats => [:html], :status => 404, :layout => false
  end

  def auth_hash
    request.env["omniauth.auth"]
  end
end
