class UsersController < ApplicationController
  def update
    @user.update(user_params)
    @user.admin = params[:admin] if params[:admin]
  end

  def user_params
    params.require(:user).permit!
  end
end
