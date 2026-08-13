class AddPermissionsToPersonalAccessTokens < ActiveRecord::Migration[7.2]
  def change
    # NULL, the value every existing row gets, means "not restricted": tokens
    # issued before scopes existed keep the full access they were created with.
    add_column :personal_access_tokens, :permissions, :text, null: true
  end
end
