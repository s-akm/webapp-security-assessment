# 架空の題材: パスワードの長さの規則
class Member < ApplicationRecord
  validates :password, presence: true,
                       confirmation: true,
                       length: { minimum: 6 }
  validates :nickname, length: { minimum: 2 }
end
