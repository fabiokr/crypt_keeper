module CryptKeeper
  module Helper
    module SQL
      private

      # Private: Sanitize an sql query and then execute it
      #
      # query - the prepared statement query
      # binds - a hash of binds of values for the prepared statement. Example:
      #         { "value" => "thevalue", "key" => "thekey" }
      def escape_and_execute_sql(query, binds)
        prepared_statement_binds = binds.map do |k, v|
          ActiveRecord::Relation::QueryAttribute.new(k, v, ActiveModel::Type::String.new)
        end

        ::ActiveRecord::Base.connection.exec_query(query, nil, prepared_statement_binds).first
      end
    end

    module DigestPassphrase
      def digest_passphrase(key, salt)
        raise ArgumentError.new("Missing :key") if key.blank?
        raise ArgumentError.new("Missing :salt") if salt.blank?
        ::Armor.digest(key, salt)
      end
    end
  end
end
