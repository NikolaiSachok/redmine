class CreateApiAuditEvents < ActiveRecord::Migration[7.2]
  def change
    create_table :api_audit_events do |t|
      # Both identities, always. user_id is who the request acted as;
      # impersonator_id is who actually held the credential when
      # X-Redmine-Switch-User was used, and is NULL otherwise.
      t.integer :user_id
      t.integer :impersonator_id
      # Denormalised so the evidence survives the account being deleted, which
      # is exactly what somebody covering their tracks would do next.
      t.string :login, :limit => 60
      t.string :impersonator_login, :limit => 60
      t.string :credential_type, :limit => 30
      # The token is referenced by id. Its value is never stored -- only a
      # digest of it exists anywhere, and not here.
      t.integer :personal_access_token_id
      t.string :http_method, :limit => 10
      t.string :endpoint, :limit => 255
      t.string :path, :limit => 255
      t.string :ip, :limit => 45
      t.integer :status
      t.datetime :created_on, :null => false
    end
    # created_on carries the default time window of the admin screen and the
    # whole of the prune task, so it is the one index that has to exist.
    add_index :api_audit_events, :created_on
    add_index :api_audit_events, :user_id
  end
end
