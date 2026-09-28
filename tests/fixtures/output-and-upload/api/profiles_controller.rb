class ProfilesController < ApplicationController
  def avatar
    picked = params[:member][:photo_upload]
    File.binwrite(Rails.root.join("public", picked.original_filename), picked.read)
  end
end
