class PagesController < ApplicationController
  def show
    render plain: "#{id}-#{hash}"
  end
end
