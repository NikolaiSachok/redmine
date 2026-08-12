class CreatePersonalAccessTokens < ActiveRecord::Migration[7.2]
  def change
    create_table :personal_access_tokens do |t|
      t.references :user, null: false
      t.string :name, null: false
      t.string :token_digest, limit: 64, null: false
      t.date :expires_on
      t.datetime :last_used_on
      t.timestamps null: false
    end
    add_index :personal_access_tokens, :token_digest, unique: true
    add_index :personal_access_tokens, [:user_id, :name], unique: true
  end
end
