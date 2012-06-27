class AddAuthFieldsToAuthorizations < ActiveRecord::Migration
  def change
    add_column :spree_user_authentications,:oauth_token,:string
    add_column :spree_user_authentications,:oauth_expires_at,:datetime
  end
end
